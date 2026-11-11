"""Terminal output with Rich."""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table as RichTable
from rich.text import Text

from .models import CheckResult, Status, Table
from .runner import Diagnosis
from .target import Target

STYLE = {
    Status.PASS: ("PASS", "bold green", "green"),
    Status.INFO: ("INFO", "bold cyan", "cyan"),
    Status.WARN: ("WARN", "bold yellow", "yellow"),
    Status.FAIL: ("FAIL", "bold red", "red"),
    Status.SKIP: ("SKIP", "dim", "bright_black"),
    Status.ERROR: ("ERROR", "bold magenta", "magenta"),
}


def badge(status: Status) -> Text:
    label, style, _ = STYLE[status]
    return Text(f" {label} ", style=f"{style} reverse")


def _table(t: Table) -> RichTable:
    rt = RichTable(title=t.title, title_justify="left", title_style="bold", box=box.SIMPLE_HEAD, pad_edge=False,
                   show_edge=False, expand=False)
    for col in t.columns:
        rt.add_column(col, overflow="fold")
    for row in t.rows:
        rt.add_row(*[str(c) for c in row])
    return rt


def render_header(console: Console, target: Target, env: dict) -> None:
    line = Text.assemble(("NetDoctor ", "bold"), (f"{env.get('netdoctor', '')}  ", "dim"),
                         ("target ", "dim"), (target.url or target.endpoint, "bold cyan"))
    sub = Text(f"{env.get('hostname')} · {env.get('os')} · ICMP engine: {env.get('icmp_engine')}", style="dim")
    console.print(Panel(Group(line, sub), box=box.ROUNDED, border_style="bright_black"))


def render_result(console: Console, r: CheckResult, show_commands: bool = True) -> None:
    _, _, border = STYLE[r.status]
    parts: list = []
    if r.summary:
        parts.append(Text(r.summary, style="bold" if r.status in (Status.FAIL, Status.WARN) else ""))
    for line in r.evidence:
        parts.append(Text("• " + line))
    for t in r.tables:
        if t.rows:
            parts.append(Text(""))
            parts.append(_table(t))
    shown = [f for f in r.findings if f.message != r.summary or len(r.findings) > 1]
    if shown:
        parts.append(Text(""))
        for f in shown:
            label, style, _ = STYLE[f.status]
            parts.append(Text.assemble((f"{label:<5} ", style), (f"{f.code}  ", "dim"), f.message))
    if show_commands and r.commands:
        parts.append(Text(""))
        parts.append(Text("Reproduce by hand: " + "  |  ".join(r.commands), style="dim"))
    title = Text.assemble((f"{r.layer}", "bold"), "  ", (r.title, ""))
    subtitle = Text.assemble(badge(r.status), (f" {r.duration_ms / 1000:.1f}s", "dim"))
    console.print(Panel(Group(*parts) if parts else Text(""), title=title, title_align="left", subtitle=subtitle,
                        subtitle_align="right", border_style=border, box=box.ROUNDED, padding=(0, 1)))


CONF_STYLE = {"High": "bold green", "Medium": "bold yellow", "Low": "bold red"}


def render_verdict(console: Console, verdict: dict, report_path: str | None = None) -> None:
    style = "green" if verdict["root_cause_id"] == "no_fault" else "red" if verdict["confidence"] >= 0.6 else "yellow"
    parts: list = [
        Text.assemble(("Root cause  ", "dim"), (verdict["title"], "bold"), ("  " + verdict["root_cause_id"], "dim")),
        Text.assemble(("Confidence  ", "dim"), (f"{verdict['confidence_label']} ({verdict['confidence']:.2f})",
                                                 CONF_STYLE.get(verdict["confidence_label"], "")),
                      ("   Layer ", "dim"), verdict["layer"], ("   Owner ", "dim"), verdict["owner"] or "-"),
        Text(""),
        Text(verdict["explanation"]),
    ]
    if verdict["resolution"]:
        parts.append(Text(""))
        parts.append(Text("Resolution", style="bold"))
        for i, step in enumerate(verdict["resolution"][:4], 1):
            parts.append(Text(f"{i}. {step}"))
    if verdict.get("other_findings"):
        parts.append(Text(""))
        parts.append(Text(f"{len(verdict['other_findings'])} other problem(s) not explained by this root cause "
                          "(see the report).", style="yellow"))
    if report_path:
        parts.append(Text(""))
        parts.append(Text(f"Incident report: {report_path}", style="dim"))
    console.print(Panel(Group(*parts), title=Text("Verdict", style="bold"), title_align="left", border_style=style,
                        box=box.HEAVY, padding=(0, 1)))


def render_summary(console: Console, diag: Diagnosis) -> None:
    rt = RichTable(title="Summary (bottom-up)", title_justify="left", title_style="bold", box=box.SIMPLE_HEAD)
    rt.add_column("Layer")
    rt.add_column("Check")
    rt.add_column("Result")
    rt.add_column("Finding", overflow="fold", ratio=1)
    rt.add_column("Time", justify="right")
    for r in diag.results:
        rt.add_row(r.layer, r.id, badge(r.status), r.summary, f"{r.duration_ms / 1000:.1f}s")
    console.print(rt)
    problems = [(r, f) for r in diag.results for f in r.findings if f.status in (Status.FAIL, Status.WARN)]
    if problems:
        console.print(Text("Problems found (in test order):", style="bold"))
        for r, f in problems:
            label, style, _ = STYLE[f.status]
            console.print(Text.assemble(("  " + label + " ", style), (f"[{r.id}] ", "dim"), f.message))
    else:
        console.print(Text("No problems found at any layer.", style="bold green"))
    console.print(Text(f"Finished in {diag.duration_s:.1f}s.", style="dim"))
