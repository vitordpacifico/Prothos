import asyncio
import json
import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class DNSQuery:
    received_at: str
    source_ip:   str
    qname:       str
    qtype:       str
    matched_id:  Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class DNSLogReport:
    domain:      str
    listen:      str
    started_at:  str                = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]     = None
    queries:     list[DNSQuery]    = field(default_factory=list)
    errors:      list[str]         = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["queries"] = [q.to_dict() for q in self.queries]
        return d


QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
          16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def generate_subdomain(domain: str, id: Optional[str] = None) -> str:
    cid = id or uuid.uuid4().hex[:12]
    return f"{cid}.{domain}"


def _parse_qname(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("latin-1", "replace"))
        offset += length
    return ".".join(labels), offset


def _build_response(data: bytes, resolve_ip: str) -> Optional[bytes]:
    try:
        tid = data[:2]
        flags = b"\x81\x80"
        qdcount = data[4:6]
        ancount = b"\x00\x01"
        header = tid + flags + qdcount + ancount + b"\x00\x00\x00\x00"

        qname, end = _parse_qname(data, 12)
        question = data[12:end + 4]

        answer = (
            b"\xc0\x0c"
            + b"\x00\x01"
            + b"\x00\x01"
            + b"\x00\x00\x00\x3c"
            + b"\x00\x04"
            + bytes(int(o) for o in resolve_ip.split("."))
        )
        return header + question + answer
    except Exception:
        return None


class _DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, report: DNSLogReport, domain: str, resolve_ip: str, expected: list[str]):
        self.report = report
        self.domain = domain.lower()
        self.resolve_ip = resolve_ip
        self.expected = expected
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        try:
            qname, end = _parse_qname(data, 12)
            qtype_num = struct.unpack(">H", data[end:end + 2])[0] if end + 2 <= len(data) else 1
            qname_l = qname.lower()

            if self.domain in qname_l:
                matched = None
                for cid in self.expected:
                    if cid and cid in qname_l:
                        matched = cid
                        break
                q = DNSQuery(
                    received_at=datetime.now(timezone.utc).isoformat(),
                    source_ip=addr[0], qname=qname_l,
                    qtype=QTYPES.get(qtype_num, str(qtype_num)),
                    matched_id=matched,
                )
                self.report.queries.append(q)
                _print_query(q)

            resp = _build_response(data, self.resolve_ip)
            if resp and self.transport:
                self.transport.sendto(resp, addr)
        except Exception as e:
            self.report.errors.append(str(e)[:120])


def _print_query(q: DNSQuery):
    tag = f"[green](matched {q.matched_id})[/green]" if q.matched_id else ""
    console.print(
        f"  [bold red][DNS][/bold red] "
        f"[cyan]{q.source_ip}[/cyan] "
        f"[white]{q.qtype} {q.qname}[/white] {tag}"
    )


def _display(report: DNSLogReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.domain}[/bold white] @ {report.listen}  "
        f"[dim]queries:[/dim] [yellow]{len(report.queries)}[/yellow]  "
        f"[dim]matched:[/dim] [green]{sum(1 for q in report.queries if q.matched_id)}[/green]",
        title="[bold red]DNS OOB Log — Summary[/bold red]",
        border_style="red",
    ))

    if not report.queries:
        console.print("[dim]    No DNS queries received.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Time",   style="dim", width=22)
    table.add_column("Source", style="cyan", width=18)
    table.add_column("Type",   style="white", width=8)
    table.add_column("Query",  style="yellow", min_width=30)
    table.add_column("ID",     style="green", width=14)

    for q in report.queries:
        table.add_row(q.received_at[11:19], q.source_ip, q.qtype, q.qname[:45], q.matched_id or "-")

    console.print(table)
    console.print()


async def _serve(domain, host, port, duration, resolve_ip, expected) -> DNSLogReport:
    report = DNSLogReport(domain=domain, listen=f"{host}:{port}")
    loop = asyncio.get_running_loop()

    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DNSProtocol(report, domain, resolve_ip, expected),
            local_addr=(host, port),
        )
    except Exception as e:
        report.errors.append(f"bind failed: {e}")
        console.print(f"[red][!] Could not bind UDP {host}:{port} — {e} (port 53 needs privileges)[/red]")
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report

    console.print(f"[dim]    Listening UDP {host}:{port} for {duration}s — Ctrl+C to stop early[/dim]")
    try:
        await asyncio.sleep(duration)
    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("[yellow]    [!] Interrupted, stopping listener[/yellow]")
    finally:
        transport.close()

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_dns_log(
    domain:      str,
    listen_host: str            = "0.0.0.0",
    listen_port: int            = 53,
    duration:    int            = 300,
    resolve_ip:  str            = "127.0.0.1",
    expected_ids: Optional[list[str]] = None,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> DNSLogReport:

    console.print(f"\n[bold red][*][/bold red] DNS OOB Log → [bold white]{domain}[/bold white]")

    try:
        report = asyncio.run(_serve(domain, listen_host, listen_port, duration, resolve_ip, expected_ids or []))
    except KeyboardInterrupt:
        report = DNSLogReport(domain=domain, listen=f"{listen_host}:{listen_port}")
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
