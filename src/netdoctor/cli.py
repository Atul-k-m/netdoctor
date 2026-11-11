"""Command-line interface."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .checks import CHECK_IDS
from .context import Options
from .models import Status
from .target import parse_target

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="NetDoctor: test a failing URL or host layer by layer, find the root cause, write the ticket notes.",
)


def _ids(value: str | None, option: str) -> set[str] | None:
    if not value:
        return None
    ids = {v.strip().lower() for v in value.split(",") if v.strip()}
    unknown = ids - set(CHECK_IDS)
    if unknown:
        raise typer.BadParameter(f"unknown check(s) {', '.join(sorted(unknown))}; choose from {', '.join(CHECK_IDS)}",
                                 param_hint=option)
    return ids


@app.callback()
def main() -> None:
    """NetDoctor network troubleshooting toolkit."""


@app.command()
def diagnose(
    target: str = typer.Argument(..., help="URL, host, host:port or IP, e.g. https://example.com/login"),
    port: int | None = typer.Option(None, "--port", "-p", help="Port to test (overrides the URL)."),
    count: int = typer.Option(20, "--count", "-c", min=1, max=500, help="ICMP echo requests for the ping check."),
    max_hops: int = typer.Option(30, "--max-hops", min=1, max=64, help="Traceroute TTL limit."),
    rounds: int = typer.Option(10, "--rounds", min=0, max=100, help="MTR rounds per hop after the first trace."),
    probe_timeout: float = typer.Option(1.5, "--probe-timeout", min=0.2, max=10, help="Seconds to wait per ICMP probe."),
    only: str | None = typer.Option(None, "--only", help=f"Run only these checks: {','.join(CHECK_IDS)}"),
    skip: str | None = typer.Option(None, "--skip", help="Skip these checks."),
    no_scan: bool = typer.Option(False, "--no-scan", help="Skip the common-port scan."),
    no_rdns: bool = typer.Option(False, "--no-rdns", help="Don't reverse-resolve traceroute hops."),
    proxy: str | None = typer.Option(None, "--proxy", help="Test through this HTTP proxy (http://host:port)."),
    no_proxy: bool = typer.Option(False, "--no-proxy", help="Ignore proxy settings and go direct."),
    quick: bool = typer.Option(False, "--quick", help="Fewer probes: 5 pings, 3 MTR rounds, no port scan."),
    json_out: str | None = typer.Option(None, "--json", help="Write all evidence as JSON to this file ('-' = stdout)."),
    brief: bool = typer.Option(False, "--brief", help="Only print the summary table."),
    no_capture: bool = typer.Option(False, "--no-capture", help="Don't capture packets during the run."),
    capture_tool: str = typer.Option("auto", "--capture-tool",
                                     help="auto | dumpcap | pktmon (Windows) | tcpdump (Linux)."),
    out: Path | None = typer.Option(None, "--out",
                                    help="Run folder for report.md, report.json, capture.pcap (default runs/<time>-<host>)."),
    no_save: bool = typer.Option(False, "--no-save", help="Write nothing to disk (no report, no capture)."),
) -> None:
    """Diagnose a URL or host bottom-up: local, DNS, ICMP, path, TCP, path MTU, TLS, HTTP.

    Ends with a verdict (root cause, confidence, next steps) and writes an incident report.
    Packets are captured during the run when there are rights to (admin/root; see --no-capture)."""
    from .render import render_header, render_result, render_summary, render_verdict
    from .runner import run_diagnosis
    from .verdict import evaluate, write_report

    try:
        tgt = parse_target(target, port)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="TARGET") from exc
    if capture_tool not in ("auto", "dumpcap", "pktmon", "tcpdump"):
        raise typer.BadParameter("choose auto, dumpcap, pktmon or tcpdump", param_hint="--capture-tool")
    run_dir = out or default_run_dir(tgt.host)

    opts = Options(
        count=5 if quick else count,
        max_hops=max_hops,
        mtr_rounds=3 if quick else rounds,
        probe_timeout=probe_timeout,
        scan=not (no_scan or quick),
        rdns=not no_rdns,
        proxy=proxy,
        no_proxy=no_proxy,
        only=_ids(only, "--only"),
        skip=_ids(skip, "--skip") or set(),
        capture=not (no_capture or no_save),
        capture_tool=capture_tool,
        out_dir=run_dir,
    )
    to_stdout = json_out == "-"
    console = Console(stderr=to_stdout, highlight=False)
    quiet = to_stdout
    if not quiet:
        from .context import RunContext
        from .runner import environment

        render_header(console, tgt, environment(RunContext(tgt, opts)))
    status_line = None if quiet else console.status("Starting…", spinner="dots")
    if status_line:
        status_line.start()

    def on_start(module) -> None:
        if status_line:
            status_line.update(f"[bold]{module.LAYER}[/] {module.TITLE}…")

    def on_done(result) -> None:
        if not quiet and not brief:
            render_result(console, result)

    def on_capture(session, error) -> None:
        if quiet:
            return
        if session is not None:
            console.print(f"[dim]Capturing packets with {session.tool} on {session.interface} -> {session.path}[/]")
        else:
            console.print(f"[yellow]Packet capture off:[/] {error}")

    try:
        diag = run_diagnosis(tgt, opts, on_start, on_done, on_capture)
    finally:
        if status_line:
            status_line.stop()

    report = diag.to_dict()
    verdict = evaluate(report)
    md_path = None
    if not no_save:
        md_path, _js = write_report(run_dir, report, verdict)
    if not quiet:
        render_summary(console, diag)
        render_verdict(console, verdict, str(md_path) if md_path else None)
    if json_out:
        payload = json.dumps({"verdict": verdict, "diagnosis": report}, indent=2, default=str)
        if to_stdout:
            sys.stdout.write(payload + "\n")
        else:
            out = Path(json_out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(payload, encoding="utf-8")
            console.print(f"[dim]Evidence written to {json_out}[/]")
    raise typer.Exit(1 if diag.status == Status.FAIL else 0)


def default_run_dir(host: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9.-]+", "_", host)[:60]
    return Path("runs") / f"{stamp}-{safe}"


@app.command()
def pcap(
    file: Path = typer.Argument(..., exists=True, dir_okay=False, help="A .pcap or .pcapng file (any source)."),
    focus: list[str] = typer.Option([], "--focus", "-f", help="Judge only flows to this server ip:port (repeatable)."),
    json_out: bool = typer.Option(False, "--json", help="Print the raw summary as JSON."),
) -> None:
    """Summarize a capture: handshakes, retransmissions, RSTs, zero windows, TLS alerts, DNS errors, ICMP."""
    from .capture import build_result, summarize_file
    from .render import render_result

    targets = []
    for item in focus:
        host, _, port = item.rpartition(":")
        if not host or not port.isdigit():
            raise typer.BadParameter(f"expected ip:port, got {item!r}", param_hint="--focus")
        targets.append((host.strip("[]"), int(port)))
    summary = summarize_file(file, targets)
    if json_out:
        sys.stdout.write(json.dumps(summary, indent=2, default=str) + "\n")
        return
    render_result(Console(highlight=False), build_result(summary, {"file": str(file), "tool": "file"}),
                  show_commands=False)


@app.command("report")
def report_cmd(
    file: Path = typer.Argument(..., exists=True, dir_okay=False,
                                help="report.json from a run, or the JSON written by --json."),
    out: Path | None = typer.Option(None, "--out", help="Folder for the new report.md (default: next to FILE)."),
) -> None:
    """Re-run the verdict engine on saved evidence and rewrite the incident report."""
    from .render import render_verdict
    from .verdict import evaluate, render_markdown

    data = json.loads(file.read_text(encoding="utf-8"))
    report = data.get("diagnosis", data)
    if "checks" not in report:
        raise typer.BadParameter("no NetDoctor evidence in this file", param_hint="FILE")
    verdict = evaluate(report)
    target_dir = out or file.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    md = target_dir / "report.md"
    md.write_text(render_markdown(report, verdict), encoding="utf-8")
    render_verdict(Console(highlight=False), verdict, str(md))


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"netdoctor {__version__}")
