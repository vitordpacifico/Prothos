import asyncio
import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

WS_PATHS = ["/ws", "/wss", "/websocket", "/socket", "/socket.io/?EIO=4&transport=websocket",
            "/cable", "/api/ws", "/live", "/stream", "/graphql", "/signalr"]

EVIL_ORIGIN = "https://prothos-cswsh-canary.example"

SEVERITY_COLOR = {
    "critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "cyan",
}


@dataclass
class WebSocketFinding:
    kind:       str
    endpoint:   str
    detail:     str
    severity:   str          = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class WebSocketReport:
    target:      str
    started_at:  str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None
    endpoints:   list[str]                = field(default_factory=list)
    findings:    list[WebSocketFinding]   = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    @property
    def high(self) -> list[WebSocketFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def _handshake_headers(origin: Optional[str] = None) -> dict:
    h = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Key": _ws_key(),
        "Sec-WebSocket-Version": "13",
    }
    if origin:
        h["Origin"] = origin
    return h


def _add(report, kind, endpoint, detail, severity):
    f = WebSocketFinding(kind=kind, endpoint=endpoint, detail=detail, severity=severity)
    report.findings.append(f)
    _print_finding(f)


async def _handshake(client, url, origin=None):
    try:
        r = await client.get(url, headers=_handshake_headers(origin), timeout=10)
        return r
    except Exception:
        return None


async def _analyze(client, http_url, ws_url, report):
    r = await _handshake(client, http_url)
    if r is None:
        return
    upgraded = (r.status_code == 101 or "websocket" in r.headers.get("upgrade", "").lower())
    if not upgraded:
        return

    report.endpoints.append(ws_url)
    secure = ws_url.startswith("wss://")
    if not secure:
        _add(report, "Unencrypted WebSocket", ws_url, "Endpoint uses ws:// (no TLS)", "medium")

    r_evil = await _handshake(client, http_url, origin=EVIL_ORIGIN)
    if r_evil is not None and (r_evil.status_code == 101 or "websocket" in r_evil.headers.get("upgrade", "").lower()):
        _add(report, "CSWSH", ws_url,
             "Handshake accepted with foreign Origin — cross-site WebSocket hijacking possible", "high")

    auth_headers = {k.lower() for k in r.request.headers}
    if "authorization" not in auth_headers and "cookie" not in auth_headers:
        _add(report, "No auth on handshake", ws_url,
             "Handshake succeeds without Authorization/Cookie — verify auth model", "low")


def _print_finding(f: WebSocketFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.kind}[/bold white] → [yellow]{f.detail}[/yellow] [dim]{f.endpoint}[/dim]"
    )


def _display(report: WebSocketReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]ws endpoints:[/dim] {len(report.endpoints)}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]WebSocket Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.endpoints:
        console.print("[dim]    No WebSocket endpoint found.[/dim]\n")
        return
    console.print(f"[dim]    Endpoints: {', '.join(report.endpoints)}[/dim]")

    if not report.findings:
        console.print("[dim]    No WebSocket issues found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Kind",     style="cyan", width=22)
    table.add_column("Detail",   style="yellow", min_width=35)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.kind, f.detail[:50])

    console.print(table)
    console.print()


async def _ws_async(target, concurrency, proxy) -> WebSocketReport:
    report = WebSocketReport(target=target)
    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"
    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    sem = asyncio.Semaphore(concurrency)

    candidates = []
    base_path = target if parsed.path and parsed.path != "/" else None
    if base_path:
        candidates.append((target, target.replace("http", "ws", 1)))
    for p in WS_PATHS:
        http_url = urljoin(root, p)
        ws_url = f"{ws_scheme}://{parsed.netloc}{p}"
        candidates.append((http_url, ws_url))

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as progress:
            progress.add_task("Scanning WebSockets...", total=None)

            async def _one(http_url, ws_url):
                async with sem:
                    await _analyze(client, http_url, ws_url, report)

            await asyncio.gather(*[_one(h, w) for h, w in candidates])

    report.findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_websocket_scan(
    target:      str,
    concurrency: int            = 10,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> WebSocketReport:

    console.print(f"\n[bold red][*][/bold red] WebSocket Scan → [bold white]{target}[/bold white]")

    report = asyncio.run(_ws_async(target, concurrency, proxy))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
