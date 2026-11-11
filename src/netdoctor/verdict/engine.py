"""Evaluate the rules against a run's evidence and produce the verdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

from .facts import SafeDict, extract, findings
from .rules import NO_FAULT, RULES, UNCLASSIFIED, Rule

# Findings that are not problems once a higher layer reached the service: the classic
# "ping fails but the site works" because ICMP is filtered.
REACHED = ("tcp.open", "tcp.proxy_ok", "tls.ok", "http.ok", "http.proxy_ok", "capture.handshakes")
BENIGN_IF_REACHED = {
    "icmp.no_reply": "ICMP echo is filtered, but the service answered over TCP: not a fault.",
    "path.stops": "Traceroute goes silent because ICMP is filtered further along; the service itself is reachable.",
    "path.silent": "Routers don't answer traceroute probes (ICMP filtered); the service itself is reachable.",
}


def label(score: float) -> str:
    if score >= 0.85:
        return "High"
    if score >= 0.6:
        return "Medium"
    return "Low"


@dataclass
class Candidate:
    rule: Rule
    score: float
    order: int
    triggers: list[str] = field(default_factory=list)
    support: list[tuple[str, float]] = field(default_factory=list)
    against: list[tuple[str, float]] = field(default_factory=list)


def _code(spec: str) -> str:
    return spec.split(":", 1)[0]


def _match(spec: str, fs: dict[str, dict]) -> bool:
    code, _, status = spec.partition(":")
    f = fs.get(code)
    return f is not None and (not status or f["status"] == status)


def _explained(code: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch(code, p) for p in patterns)


def _fmt(text: str, facts: SafeDict) -> str:
    try:
        return text.format_map(facts)
    except (ValueError, IndexError):
        return text


def candidates(report: dict) -> tuple[list[Candidate], dict[str, dict], SafeDict]:
    fs = findings(report)
    facts = extract(report)
    first_fail = next((f for f in fs.values() if f["status"] == "fail"), None)
    facts["first_fail"] = first_fail["message"] if first_fail else "?"
    out: list[Candidate] = []
    for i, rule in enumerate(RULES):
        triggers = [s for s in rule.any_of if _match(s, fs)]
        if not triggers:
            continue
        if rule.all_of and not all(_match(s, fs) for s in rule.all_of):
            continue
        if any(_match(s, fs) for s in rule.unless):
            continue
        if rule.predicate is not None and not rule.predicate(facts):
            continue
        sup = [(s, d) for s, d in rule.support if _match(s, fs)]
        ag = [(s, d) for s, d in rule.against if _match(s, fs)]
        score = rule.base + sum(d for _s, d in sup) - sum(d for _s, d in ag)
        out.append(Candidate(rule, round(min(0.99, max(0.05, score)), 2), i,
                             [_code(s) for s in triggers + list(rule.all_of)], sup, ag))
    if not any(f["status"] == "fail" for f in fs.values()):
        out.append(Candidate(NO_FAULT, NO_FAULT.base, len(RULES)))
    if not out:
        out.append(Candidate(UNCLASSIFIED, UNCLASSIFIED.base, len(RULES) + 1))
    out.sort(key=lambda c: (-c.score, c.order))
    return out, fs, facts


def layer_walk(report: dict) -> tuple[str | None, list[str]]:
    """First failing layer, and the layers below it that passed."""
    passed: list[str] = []
    for c in report.get("checks", []):
        if c["id"] == "capture":
            continue
        if c["status"] == "fail":
            return c["layer"], passed
        if c["status"] in ("pass", "info", "warn"):
            passed.append(c["layer"])
    return None, passed


def evaluate(report: dict) -> dict:
    cands, fs, facts = candidates(report)
    primary = cands[0]
    rule = primary.rule
    own = set(primary.triggers) | {_code(s) for s, _ in primary.support}
    explained = {code for code in fs if code in own or _explained(code, rule.explains)}

    def item(code: str) -> dict:
        f = fs[code]
        return {"check": f["check"], "code": code, "status": f["status"], "message": f["message"]}

    evidence = [item(c) for c in dict.fromkeys(primary.triggers + [_code(s) for s, _ in primary.support]) if c in fs]
    contradicting = [item(_code(s)) for s, _ in primary.against if _code(s) in fs]
    reached = any(code in fs for code in REACHED)
    notes = []
    other = []
    for code, f in fs.items():
        if f["status"] not in ("fail", "warn", "error") or code in explained:
            continue
        if reached and code in BENIGN_IF_REACHED:
            notes.append({**item(code), "note": BENIGN_IF_REACHED[code]})
        else:
            other.append(item(code))
    alternatives = []
    for c in cands[1:6]:
        covered = all(t in explained for t in c.triggers) if c.triggers else False
        alternatives.append({"id": c.rule.id, "category": c.rule.category, "title": _fmt(c.rule.title, facts),
                             "confidence": c.score, "explained_by_root_cause": covered})
    first_layer, passed = layer_walk(report)
    return {
        "root_cause_id": rule.id,
        "category": rule.category,
        "title": _fmt(rule.title, facts),
        "layer": rule.layer,
        "confidence": primary.score,
        "confidence_label": label(primary.score),
        "score": {"base": rule.base, "support": [{"code": _code(s), "delta": d} for s, d in primary.support],
                  "against": [{"code": _code(s), "delta": -d} for s, d in primary.against]},
        "symptom": _fmt(rule.symptom, facts) if rule.symptom else "",
        "explanation": _fmt(rule.explanation, facts),
        "resolution": [_fmt(x, facts) for x in rule.resolution],
        "next_steps": [_fmt(x, facts) for x in rule.next_steps],
        "owner": rule.owner,
        "engineering": [_fmt(x, facts) for x in rule.engineering],
        "wireshark": list(rule.wireshark),
        "evidence": evidence,
        "contradicting": contradicting,
        "alternatives": alternatives,
        "other_findings": other,
        "notes": notes,
        "first_failing_layer": first_layer,
        "layers_passed": passed,
        "facts": {k: v for k, v in facts.items() if isinstance(v, (str, int, float, bool)) or v is None},
    }
