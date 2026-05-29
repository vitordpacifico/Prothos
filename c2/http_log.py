import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class HTTPCallback:
    received_at: str
    source_ip:   str
    method:      str
    path:        str
    headers:     dict
    body:        str          = ""
    matched_id:  Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class HTTPLogReport:
    host:        str
    port:        int
    started_at:  str                   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]        = None
    callbacks:   list[HTTPCallback]   = field(default_factory=list)
    errors:      list[str]            = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["callbacks"] = [c.to_dict() for c in self.callbacks]
        return d


def generate_callback_url(host: str, port: int, id: Optional[str] = None) -> str:
    cid = id or uuid.uuid4().hex[:12]
    scheme = "https" if port == 443 else "http"
    if port in (80, 443):
        return f"{scheme}://{host}/{cid}"
    return f"{scheme}://{host}:{port}/{cid}"


def _match_id(path: str, headers: dict, body: str, expected: list[str]) -> Optional[str]:
    blob = f"{path} {body} " + " ".join(f"{k}:{v}" for k, v in headers.items())
    for cid in expected:
        if cid and cid in blob:
            return cid
    return None


async def _handle(reader, writer, report, expected):
    try:
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"

        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
        line = request_line.decode("latin-1", "replace").strip()
        parts = line.split(" ")
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else ""

        headers = {}
        while True:
            raw = await asyncio.wait_for(reader.readline(), timeout=10)
            if raw in (b"\r\n", b"\n", b""):
                break
            decoded = raw.decode("latin-1", "replace").strip()
            if ":" in decoded:
                k, v = decoded.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        body = ""
        length = int(headers.get("content-length", 0) or 0)
        if length > 0:
            body_bytes = await asyncio.wait_for(reader.read(min(length, 65536)), timeout=10)
            body = body_bytes.decode("utf-8", "replace")

        cb = HTTPCallback(
            received_at=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip, method=method, path=path,
            headers=headers, body=body[:4000],
            matched_id=_match_id(path, headers, body, expected),
        )
        report.callbacks.append(cb)
        _print_callback(cb)

        response = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Prothos\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n\r\nok"
        )
        writer.write(response.encode())
        await writer.drain()
    except Exception as e:
        report.errors.append(str(e)[:120])
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _print_callback(cb: HTTPCallback):
    tag = f"[green](matched {cb.matched_id})[/green]" if cb.matched_id else ""
    console.print(
        f"  [bold red][HIT][/bold red] "
        f"[cyan]{cb.source_ip}[/cyan] "
        f"[white]{cb.method} {cb.path}[/white] {tag}"
    )


def _display(report: HTTPLogReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.host}:{report.port}[/bold white]  "
        f"[dim]callbacks:[/dim] [yellow]{len(report.callbacks)}[/yellow]  "
        f"[dim]matched:[/dim] [green]{sum(1 for c in report.callbacks if c.matched_id)}[/green]",
        title="[bold red]HTTP OOB Log — Summary[/bold red]",
        border_style="red",
    ))

    if not report.callbacks:
        console.print("[dim]    No callbacks received.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Time",   style="dim", width=22)
    table.add_column("Source", style="cyan", width=18)
    table.add_column("Method", style="white", width=8)
    table.add_column("Path",   style="yellow", min_width=25)
    table.add_column("ID",     style="green", width=14)

    for c in report.callbacks:
        table.add_row(c.received_at[11:19], c.source_ip, c.method, c.path[:40], c.matched_id or "-")

    console.print(table)
    console.print()


async def _serve(host, port, duration, expected) -> HTTPLogReport:
    report = HTTPLogReport(host=host, port=port)

    async def handler(reader, writer):
        await _handle(reader, writer, report, expected)

    try:
        server = await asyncio.start_server(handler, host, port)
    except Exception as e:
        report.errors.append(f"bind failed: {e}")
        console.print(f"[red][!] Could not bind {host}:{port} — {e}[/red]")
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report

    console.print(f"[dim]    Listening on {host}:{port} for {duration}s — Ctrl+C to stop early[/dim]")
    async with server:
        try:
            await asyncio.wait_for(server.serve_forever(), timeout=duration)
        except asyncio.TimeoutError:
            pass
        except (KeyboardInterrupt, asyncio.CancelledError):
            console.print("[yellow]    [!] Interrupted, stopping listener[/yellow]")

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_http_log(
    host:        str                 = "0.0.0.0",
    port:        int                 = 8080,
    duration:    int                 = 300,
    expected_ids: Optional[list[str]] = None,
    proxy:       Optional[str]       = None,
    save_json:   Optional[str]       = None,
) -> HTTPLogReport:

    console.print(f"\n[bold red][*][/bold red] HTTP OOB Log → [bold white]{host}:{port}[/bold white]")

    try:
        report = asyncio.run(_serve(host, port, duration, expected_ids or []))
    except KeyboardInterrupt:
        report = HTTPLogReport(host=host, port=port)
        report.errors.append("interrupted before bind")

    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
