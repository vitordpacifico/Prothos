import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, urljoin
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

@dataclass
class WebSocketResult:
    url:           str
    status:        int                = 0
    protocol:      Optional[str]      = None
    upgraded:      bool               = False
    interesting:   bool               = False
    notes:         list[str]          = field(default_factory=list)
    response_time: float              = 0.0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class WebSocketReport:
    target:       str
    started_at:   str                        = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:  Optional[str]             = None
    total_tested: int                        = 0
    found:        list[WebSocketResult]      = field(default_factory=list)
    errors:       list[str]                 = field(default_factory=list)

    @property
    def upgraded(self) -> list[WebSocketResult]:
        return [r for r in self.found if r.upgraded]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["found"] = [r.to_dict() for r in self.found]
        return d


WS_PATHS = [
    "/ws",
    "/websocket",
    "/socket",
    "/socket.io",
    "/socket.io/",
    "/sockjs",
    "/sockjs/",
    "/engine.io",
    "/engine.io/",
    "/ws/",
    "/wss/",
    "/realtime",
    "/live",
    "/events",
    "/stream",
    "/streaming",
    "/feed",
    "/push",
    "/notify",
    "/updates",
    "/chat",
    "/messaging",
    "/api/ws",
    "/api/websocket",
    "/api/socket",
    "/api/realtime",
    "/api/stream",
    "/api/events",
    "/api/live",
    "/v1/ws",
    "/v1/websocket",
    "/v2/ws",
    "/v2/websocket",
    "/hub",
    "/signalr",
    "/signalr/",
    "/mqtt",
    "/stomp",
    "/graphql-ws",
    "/graphql/subscriptions",
    "/subscriptions",
]

WS_INTERESTING_HEADERS = {
    "sec-websocket-protocol",
    "sec-websocket-extensions",
    "sec-websocket-version",
    "sec-websocket-key",
}

SOCKETIO_PARAMS = "?EIO=4&transport=polling"
SOCKJS_PARAMS   = "/info"


async def _probe_http(
    client: httpx.AsyncClient,
    url:    str,
    sem:    asyncio.Semaphore,
) -> Optional[WebSocketResult]:

    import time

    async with sem:
        try:
            t0 = time.perf_counter()
            r  = await client.get(url, timeout=8)
            elapsed = round(time.perf_counter() - t0, 3)

            headers = {k.lower(): v for k, v in r.headers.items()}
            body    = r.text.lower()

            if r.status_code == 404:
                return None

            notes       = []
            interesting = False
            upgraded    = False
            protocol    = None

            upgrade = headers.get("upgrade", "").lower()
            if upgrade == "websocket" or r.status_code == 101:
                upgraded    = True
                interesting = True
                notes.append("WebSocket upgrade confirmed")

            ws_protocol = headers.get("sec-websocket-protocol")
            if ws_protocol:
                protocol    = ws_protocol
                interesting = True
                notes.append(f"Protocol: {ws_protocol}")

            if any(k in headers for k in WS_INTERESTING_HEADERS):
                interesting = True
                notes.append("WS headers present")

            if "socket.io" in body or '"sid"' in body:
                interesting = True
                notes.append("Socket.IO detected")
                protocol = "socket.io"

            if "sockjs" in body:
                interesting = True
                notes.append("SockJS detected")
                protocol = "sockjs"

            if '"websocket"' in body or "websocket" in body:
                interesting = True
                notes.append("WebSocket reference in body")

            if r.status_code in (400, 426):
                interesting = True
                notes.append("WS handshake expected")

            if not interesting and r.status_code not in (200, 101, 400, 426):
                return None

            if not notes:
                return None

            return WebSocketResult(
                url=url,
                status=r.status_code,
                protocol=protocol,
                upgraded=upgraded,
                interesting=interesting,
                notes=notes,
                response_time=elapsed,
            )

        except httpx.TimeoutException:
            return None
        except Exception:
            return None


async def _probe_upgrade(
    url: str,
    sem: asyncio.Semaphore,
) -> Optional[WebSocketResult]:

    import time

    ws_url = url.replace("https://", "wss://").replace("http://", "ws://")

    async with sem:
        try:
            t0 = time.perf_counter()

            parsed  = urlparse(url)
            host    = parsed.hostname
            port    = parsed.port or (443 if parsed.scheme == "https" else 80)
            path    = parsed.path or "/"
            ssl_ctx = parsed.scheme in ("https", "wss")

            key     = "dGhlIHNhbXBsZSBub25jZQ=="
            handshake = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            ).encode()

            if ssl_ctx:
                import ssl
                ctx    = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=5,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=5,
                )

            writer.write(handshake)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=3)
            elapsed  = round(time.perf_counter() - t0, 3)
            text     = response.decode("utf-8", errors="replace")

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if "101" in text and "websocket" in text.lower():
                notes = ["WebSocket upgrade successful via raw handshake"]
                protocol = None
                m = re.search(r"Sec-WebSocket-Protocol:\s*(\S+)", text, re.IGNORECASE)
                if m:
                    protocol = m.group(1)
                    notes.append(f"Protocol: {protocol}")

                return WebSocketResult(
                    url=ws_url,
                    status=101,
                    protocol=protocol,
                    upgraded=True,
                    interesting=True,
                    notes=notes,
                    response_time=elapsed,
                )

        except Exception:
            pass

    return None


def _display(report: WebSocketReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]tested:[/dim] {report.total_tested}  "
        f"[dim]found:[/dim] [green]{len(report.found)}[/green]  "
        f"[dim]upgraded:[/dim] [red]{len(report.upgraded)}[/red]",
        title="[bold red]WebSocket Enum — Summary[/bold red]",
        border_style="red",
    ))

    if not report.found:
        console.print("[dim]    No WebSocket endpoints found.[/dim]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold red",
        border_style="dim",
    )
    table.add_column("Status",   width=8)
    table.add_column("URL",      min_width=45, style="cyan")
    table.add_column("Protocol", width=14, style="dim")
    table.add_column("Time",     width=7,  style="dim")
    table.add_column("Notes",    min_width=30, style="yellow")

    for r in report.found:
        color    = "green" if r.upgraded else "yellow" if r.status == 200 else "dim"
        upgraded = " [red][WS][/red]" if r.upgraded else ""
        table.add_row(
            f"[{color}]{r.status}[/{color}]",
            r.url + upgraded,
            r.protocol or "-",
            f"{r.response_time}s",
            " | ".join(r.notes[:2]) if r.notes else "-",
        )

    console.print(table)

    if report.upgraded:
        console.print(f"\n[bold red][!] WebSocket endpoints confirmed:[/bold red]")
        for r in report.upgraded:
            console.print(
                f"    [red]→[/red] [cyan]{r.url}[/cyan]"
                + (f" [{r.protocol}]" if r.protocol else "")
            )

    console.print()


async def _ws_async(
    target:      str,
    concurrency: int,
    proxy:       Optional[str],
) -> WebSocketReport:

    report = WebSocketReport(target=target)
    sem    = asyncio.Semaphore(concurrency)
    base   = target.rstrip("/")

    urls = [base + path for path in WS_PATHS]
    urls += [base + path + SOCKETIO_PARAMS for path in ("/socket.io", "/engine.io")]
    urls += [base + path + SOCKJS_PARAMS for path in ("/sockjs",)]

    report.total_tested = len(urls)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        console.print(f"[dim]    Probing {len(urls)} paths via HTTP...[/dim]")

        http_tasks = [_probe_http(client, url, sem) for url in urls]
        http_results = await asyncio.gather(*http_tasks, return_exceptions=True)

        seen = set()
        for result in http_results:
            if isinstance(result, WebSocketResult) and result.url not in seen:
                seen.add(result.url)
                report.found.append(result)
                color = "green" if result.upgraded else "yellow"
                console.print(
                    f"  [{color}]{result.status}[/{color}] "
                    f"[cyan]{result.url}[/cyan] "
                    f"[dim]{' | '.join(result.notes[:1])}[/dim]"
                )

    console.print(f"[dim]    Attempting raw WS upgrade on candidates...[/dim]")

    candidates = [r.url for r in report.found if not r.upgraded][:5]
    upgrade_tasks = [_probe_upgrade(url, sem) for url in candidates]
    upgrade_results = await asyncio.gather(*upgrade_tasks, return_exceptions=True)

    for result in upgrade_results:
        if isinstance(result, WebSocketResult) and result.url not in seen:
            seen.add(result.url)
            report.found.append(result)
            console.print(
                f"  [green]101[/green] "
                f"[cyan]{result.url}[/cyan] "
                f"[dim]{' | '.join(result.notes[:1])}[/dim]"
            )

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_websocket_enum(
    target:      str,
    concurrency: int          = 15,
    proxy:       Optional[str]= None,
    save_json:   Optional[str]= None,
) -> WebSocketReport:

    console.print(
        f"\n[bold red][*][/bold red] WebSocket Enum → "
        f"[bold white]{target}[/bold white]"
    )

    report = asyncio.run(_ws_async(
        target=target,
        concurrency=concurrency,
        proxy=proxy,
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