"""Write the incident report: a knowledge-base style Markdown file plus JSON."""

from __future__ import annotations

import json
from pathlib import Path

from .. import __version__
from .facts import checks_by_id

STATUS_WORD = {"pass": "PASS", "info": "INFO", "warn": "WARN", "fail": "FAIL", "skip": "SKIP", "error": "ERROR"}
SECTIONS = ["Symptom", "Environment", "Tests run", "Evidence", "Root cause", "Resolution", "What to send to engineering"]

# Which check's tables belong in the Evidence section for each root-cause category.
EVIDENCE_CHECKS = {
    "dns": ["dns"], "path": ["icmp", "path"], "tcp": ["tcp"], "pmtu": ["pmtu", "tls"], "tls": ["tls"],
    "http": ["http"], "proxy": ["http", "tcp"], "local": ["local"], "client": ["tls", "http"], "captive": ["http", "tls"],
}


def _when(iso: str | None) -> str:
    """'2026-11-11T18:03:18+00:00' -> '2026-11-11 18:03:18 UTC'."""
    if not iso:
        return "?"
    return iso.replace("T", " ").replace("+00:00", "").replace("Z", "") + " UTC"


def _esc(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _md_table(title: str, columns: list[str], rows: list[list], limit: int = 15) -> list[str]:
    out = [f"**{title}**", "", "| " + " | ".join(_esc(c) for c in columns) + " |",
           "|" + "|".join("---" for _ in columns) + "|"]
    for row in rows[:limit]:
        out.append("| " + " | ".join(_esc(c) for c in row) + " |")
    if len(rows) > limit:
        out.append(f"| … {len(rows) - limit} more rows | " + " | ".join("" for _ in columns[1:]) + " |")
    out.append("")
    return out


def _evidence_checks(category: str) -> list[str]:
    for prefix, ids in EVIDENCE_CHECKS.items():
        if category.startswith(prefix):
            return ids
    return []


def render_markdown(report: dict, verdict: dict) -> str:
    checks = checks_by_id(report)
    env = report.get("environment", {})
    facts = verdict.get("facts", {})
    tgt = report.get("target", {})
    target = tgt.get("url") or f"{tgt.get('host')}:{tgt.get('port')}"
    lines: list[str] = []
    add = lines.append

    add(f"# {verdict['title']}")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| **Root cause** | {_esc(verdict['title'])} (`{verdict['root_cause_id']}`) |")
    add(f"| **Confidence** | {verdict['confidence_label']} ({verdict['confidence']:.2f}) |")
    add(f"| **Layer** | {verdict['layer']} |")
    add(f"| **Owner** | {_esc(verdict['owner'] or '-')} |")
    add(f"| **Target** | {_esc(target)} |")
    add(f"| **Run** | {_when(report.get('started_at'))} · NetDoctor {report.get('version', __version__)} · "
        f"{report.get('duration_s')} s |")
    add("")

    # ------------------------------------------------------------- Symptom
    add("## Symptom")
    add("")
    add(verdict["symptom"] or f"The user reports a problem reaching {target}.")
    add("")
    if verdict.get("first_failing_layer"):
        passed = ", ".join(verdict.get("layers_passed") or []) or "none"
        add(f"Observed: the first failing layer is **{verdict['first_failing_layer']}**; the layers tested below it "
            f"passed ({passed}).")
    else:
        add("Observed: no layer failed outright.")
    add("")

    # --------------------------------------------------------- Environment
    add("## Environment")
    add("")
    egress = env.get("egress") or {}
    proxy = env.get("proxy") or {}
    rows = [
        ["Client", f"{env.get('hostname')} ({env.get('os')})"],
        ["NetDoctor", f"{env.get('netdoctor')} · Python {env.get('python')} · ICMP engine {env.get('icmp_engine')}"],
        ["Egress", f"{egress.get('interface') or '?'} {egress.get('source_ip') or ''} via "
                   f"{egress.get('gateway') or facts.get('gateway') or 'on-link'}"
                   + (f" (MTU {egress.get('mtu')})" if egress.get("mtu") else "")],
        ["DNS servers", facts.get("dns_servers", "?")],
        ["Proxy", f"{proxy.get('proxy_url') or 'DIRECT'} (decided by: {proxy.get('source') or '?'})"],
        ["Security / VPN agents", facts.get("agents", "none detected")],
        ["Target", f"{target} → {env.get('target_ip') or 'unresolved'}"
                   + (f" (from {env.get('target_ip_source')})" if env.get("target_ip_source") else "")],
        ["Local time of run", env.get("local_time", "?")],
    ]
    lines += _md_table("Client and network", ["Item", "Value"], rows)

    # ----------------------------------------------------------- Tests run
    add("## Tests run")
    add("")
    trows = []
    for i, c in enumerate(report.get("checks", []), 1):
        trows.append([str(i), c["layer"], c["title"], STATUS_WORD.get(c["status"], c["status"]), c["summary"][:160],
                      f"{c['duration_ms'] / 1000:.1f} s"])
    lines += _md_table("Checks, bottom-up", ["#", "Layer", "Test", "Result", "Key result", "Time"], trows, limit=20)
    add("Reproduce by hand:")
    add("")
    for c in report.get("checks", []):
        if c.get("commands"):
            add(f"- **{c['id']}**: " + " · ".join(f"`{cmd}`" for cmd in c["commands"]))
    add("")

    # ------------------------------------------------------------ Evidence
    add("## Evidence")
    add("")
    add("Supporting the root cause:")
    add("")
    for e in verdict["evidence"] or [{"check": "-", "status": "pass", "message": "every check passed"}]:
        add(f"- **[{e['check']}] {STATUS_WORD.get(e['status'], e['status'])}**: {e['message']}")
    for e in verdict.get("contradicting", []):
        add(f"- *Against (lowers confidence)* **[{e['check']}]**: {e['message']}")
    add("")
    for cid in _evidence_checks(verdict["category"]):
        c = checks.get(cid)
        if not c or c["status"] == "skip":
            continue
        for t in c.get("tables", [])[:3]:
            if t["rows"]:
                lines += _md_table(f"{cid}: {t['title']}", t["columns"], t["rows"], limit=12)
        for ev in c.get("evidence", [])[:4]:
            add(f"- {cid}: {ev}")
        add("")
    cap = checks.get("capture")
    if cap:
        if cap["status"] == "skip":
            add(f"Packet capture: not taken ({cap['summary']}).")
        else:
            add(f"Packet capture: `{facts.get('pcap') or '?'}` ({facts.get('pcap_packets')} packets). "
                f"{cap['summary']}")
            for f in cap.get("findings", [])[:6]:
                add(f"- capture {STATUS_WORD.get(f['status'])}: {f['message']}")
        add("")

    # ---------------------------------------------------------- Root cause
    add("## Root cause")
    add("")
    add(f"**{verdict['title']}**: confidence **{verdict['confidence_label']}** ({verdict['confidence']:.2f}).")
    add("")
    add(verdict["explanation"])
    add("")
    score = verdict.get("score", {})
    parts = [f"base {score.get('base', 0):.2f}"] + [f"+{s['delta']:.2f} {s['code']}" for s in score.get("support", [])] \
        + [f"{s['delta']:.2f} {s['code']}" for s in score.get("against", [])]
    add(f"Confidence = {' '.join(parts)}.")
    add("")
    alts = [a for a in verdict.get("alternatives", []) if a["id"] != "no_fault"]
    if alts:
        add("Other explanations considered:")
        add("")
        for a in alts[:4]:
            note = " (a consequence of the root cause)" if a["explained_by_root_cause"] else ""
            add(f"- {a['title']} (`{a['id']}`, {a['confidence']:.2f}){note}")
        add("")

    # ---------------------------------------------------------- Resolution
    add("## Resolution")
    add("")
    for i, step in enumerate(verdict["resolution"], 1):
        add(f"{i}. {step}")
    add("")
    if verdict.get("next_steps"):
        add("Next steps for the support engineer:")
        add("")
        for step in verdict["next_steps"]:
            add(f"- {step}")
        add("")

    # ---------------------------------------------- What to send to engineering
    add("## What to send to engineering")
    add("")
    add(f"**Escalate to:** {verdict['owner'] or 'n/a'}")
    add("")
    add(f"- **Summary:** {verdict['title']} for {target} (confidence {verdict['confidence']:.2f}).")
    add(f"- **When:** {_when(report.get('started_at'))} (run took {report.get('duration_s')} s).")
    add(f"- **Client:** {env.get('hostname')}, egress {egress.get('source_ip') or '?'} on "
        f"{egress.get('interface') or '?'}, proxy {proxy.get('proxy_url') or 'DIRECT'}.")
    add(f"- **Destination:** {target} → {env.get('target_ip') or 'unresolved'}.")
    for item in verdict.get("engineering", []):
        add(f"- {item}")
    for e in verdict["evidence"][:4]:
        add(f"- Evidence [{e['check']}]: {e['message']}")
    attach = ["`report.json` (all evidence, machine-readable)"]
    if facts.get("pcap"):
        attach.append(f"`{Path(str(facts['pcap'])).name}`")
    add(f"- **Attachments:** {', '.join(attach)}.")
    if verdict.get("wireshark") and facts.get("pcap"):
        add("- **Wireshark filters:** " + " · ".join(f"`{w}`" for w in verdict["wireshark"]))
    add("")

    other = verdict.get("other_findings", [])
    if other:
        add("## Other observations")
        add("")
        add("Problems not explained by the root cause above (may be separate issues):")
        add("")
        for o in other:
            add(f"- **[{o['check']}] {STATUS_WORD.get(o['status'], o['status'])}** `{o['code']}`: {o['message']}")
        add("")
    notes = verdict.get("notes", [])
    if notes:
        add("## Notes")
        add("")
        for n in notes:
            add(f"- `{n['code']}` [{n['check']}]: {n['note']}")
        add("")
    add("---")
    add(f"*Generated by NetDoctor {report.get('version', __version__)}. Evidence: report.json in the same folder.*")
    return "\n".join(lines) + "\n"


def write_report(out_dir: Path, report: dict, verdict: dict) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "report.md"
    js = out_dir / "report.json"
    md.write_text(render_markdown(report, verdict), encoding="utf-8")
    js.write_text(json.dumps({"verdict": verdict, "diagnosis": report}, indent=2, default=str), encoding="utf-8")
    return md, js
