import asyncio
import json
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

DELAY_THRESHOLD = 5.0
READ_TIMEOUT = 10.0

TE_OBFUSCATIONS: list[str] = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: \x0bchunked",
    "Transfer-Encoding: chunked\r\nTransfer-encoding: cow",
    "Transfer-Encoding: xchunked",
    " Transfer-Encoding: chunked",
    "X: X\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding\r\n: chunked",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class SmugglingFinding:
    url:        str
    technique:  str
    variant:    str
    baseline:   float
    probe_time: float
    timed_out:  bool
    evidence:   str          = ""
    severity:   str          = "critical"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SmugglingReport:
    target:      str
    started_at:  str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None
    baseline:    float                    = 0.0
    findings:    list[SmugglingFinding]   = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    @property
    def critical(self) -> list[SmugglingFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _parse_target(target: str) -> tuple[str, int, bool, str]:
    parsed = urlparse(target if "://" in target else f"http://{target}")
    use_tls = parsed.scheme == "https"
    host = parsed.hostname or target
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return host, port, use_tls, path


async def _send_raw(host: str, port: int, use_tls: bool, raw: bytes,
                    read_timeout: float) -> tuple[float, bool, str]:
    ctx = None
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    t0 = time.perf_counter()
    timed_out = False
    status_line = ""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host if use_tls else None),
            timeout=read_timeout,
        )
        writer.write(raw)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=read_timeout)
            status_line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        except asyncio.TimeoutError:
            timed_out = True
    except asyncio.TimeoutError:
        timed_out = True
    except Exception as e:
        return time.perf_counter() - t0, False, f"err:{str(e)[:40]}"
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except Exception:
                pass

    return time.perf_counter() - t0, timed_out, status_line


def _normal_request(host: str, path: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0 (compatible; Prothos/1.0)\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1")


def _clte_probe(host: str, path: str, te_header: str) -> bytes:
    body = "1\r\nA\r\nX"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{te_header}\r\n"
        f"Content-Length: 4\r\n"
        f"Connection: close\r\n\r\n"
        f"{body}"
    ).encode("latin-1")


def _tecl_probe(host: str, path: str, te_header: str) -> bytes:
    body = "0\r\n\r\nX"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{te_header}\r\n"
        f"Content-Length: 6\r\n"
        f"Connection: close\r\n\r\n"
        f"{body}"
    ).encode("latin-1")


async def _run_probe(host, port, use_tls, path, technique, variant, builder, te_header,
                     baseline, sem) -> Optional[SmugglingFinding]:
    async with sem:
        raw = builder(host, path, te_header)
        elapsed, timed_out, status = await _send_raw(host, port, use_tls, raw, READ_TIMEOUT)

        if status.startswith("err:"):
            return None

        delayed = elapsed >= max(DELAY_THRESHOLD, baseline + DELAY_THRESHOLD)
        if timed_out or delayed:
            f = SmugglingFinding(
                url=f"{'https' if use_tls else 'http'}://{host}:{port}{path}",
                technique=technique, variant=variant[:40],
                baseline=round(baseline, 2), probe_time=round(elapsed, 2),
                timed_out=timed_out,
                evidence=f"probe delayed {elapsed:.1f}s vs baseline {baseline:.1f}s"
                         + (" (read timeout)" if timed_out else ""),
                severity="critical",
            )
            _print_finding(f)
            return f
    return None


def _print_finding(f: SmugglingFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.technique}[/bold white] → "
        f"[yellow]{f.evidence}[/yellow]  "
        f"[dim]{f.variant}[/dim]"
    )


def _display(report: SmugglingReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]baseline:[/dim] {report.baseline:.2f}s  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]",
        title="[bold red]Request Smuggling — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No desync detected.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Technique", style="cyan", width=12)
    table.add_column("Baseline",  style="dim", width=10)
    table.add_column("Probe",     style="dim", width=10)
    table.add_column("Evidence",  style="yellow", min_width=30)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.technique, f"{f.baseline}s", f"{f.probe_time}s", f.evidence[:45],
        )

    console.print(table)
    console.print()
    console.print("[dim]    Note: timing-based heuristic — confirm manually before reporting.[/dim]\n")


async def _smuggling_async(target, concurrency) -> SmugglingReport:
    report = SmugglingReport(target=target)
    host, port, use_tls, path = _parse_target(target)
    sem = asyncio.Semaphore(concurrency)

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=35, style="red", complete_style="green"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task("Testing desync...", total=None)

        samples = []
        for _ in range(3):
            elapsed, _, status = await _send_raw(host, port, use_tls, _normal_request(host, path), READ_TIMEOUT)
            if not status.startswith("err:"):
                samples.append(elapsed)
        report.baseline = min(samples) if samples else 0.0

        if not samples:
            report.errors.append("Could not establish baseline connection")
            progress.update(task_id, completed=1, total=1)
            report.finished_at = datetime.now(timezone.utc).isoformat()
            return report

        tasks = []
        for te in TE_OBFUSCATIONS:
            tasks.append(_run_probe(host, port, use_tls, path, "CL.TE", te,
                                    _clte_probe, te, report.baseline, sem))
            tasks.append(_run_probe(host, port, use_tls, path, "TE.CL", te,
                                    _tecl_probe, te, report.baseline, sem))

        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                report.findings.append(result)
        progress.update(task_id, completed=1, total=1)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_request_smuggling(
    target:        str,
    concurrency:   int            = 3,
    proxy:         Optional[str]  = None,
    save_json:     Optional[str]  = None,
) -> SmugglingReport:

    console.print(f"\n[bold red][*][/bold red] Request Smuggling → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Techniques: CL.TE, TE.CL, TE.TE  "
                  f"Obfuscations: {len(TE_OBFUSCATIONS)}  (timing-based)[/dim]")
    if proxy:
        console.print("[dim]    Note: proxy ignored — raw socket required for smuggling probes[/dim]")

    report = asyncio.run(_smuggling_async(
        target=target,
        concurrency=concurrency,
    ))

    _display(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
