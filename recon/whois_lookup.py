import asyncio
import json
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@dataclass
class WhoisReport:
    target:        str
    domain:        str                  = ""
    ip:            Optional[str]        = None
    registrar:     Optional[str]        = None
    registered:    Optional[str]        = None
    updated:       Optional[str]        = None
    expires:       Optional[str]        = None
    status:        list[str]            = field(default_factory=list)
    nameservers:   list[str]            = field(default_factory=list)
    org:           Optional[str]        = None
    country:       Optional[str]        = None
    asn:           Optional[str]        = None
    asn_org:       Optional[str]        = None
    cidr:          Optional[str]        = None
    raw:           Optional[str]        = None
    findings:      list[str]            = field(default_factory=list)
    started_at:    str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:   Optional[str]        = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


WHOIS_SERVERS = {
    "com":  "whois.verisign-grs.com",
    "net":  "whois.verisign-grs.com",
    "org":  "whois.pir.org",
    "io":   "whois.nic.io",
    "co":   "whois.nic.co",
    "br":   "whois.registro.br",
    "uk":   "whois.nic.uk",
    "de":   "whois.denic.de",
    "fr":   "whois.afnic.fr",
    "ru":   "whois.tcinet.ru",
    "cn":   "whois.cnnic.cn",
    "au":   "whois.auda.org.au",
    "ca":   "whois.cira.ca",
    "jp":   "whois.jprs.jp",
    "in":   "whois.registry.in",
    "info": "whois.afilias.net",
    "biz":  "whois.biz",
    "app":  "whois.nic.google",
    "dev":  "whois.nic.google",
    "ai":   "whois.nic.ai",
    "sh":   "whois.nic.sh",
}

FIELD_PATTERNS = {
    "registrar":  [
        r"Registrar:\s*(.+)",
        r"registrar:\s*(.+)",
        r"Registrar Name:\s*(.+)",
    ],
    "registered": [
        r"Creation Date:\s*(.+)",
        r"Created:\s*(.+)",
        r"created:\s*(.+)",
        r"Registration Time:\s*(.+)",
        r"Registered on:\s*(.+)",
    ],
    "updated": [
        r"Updated Date:\s*(.+)",
        r"Last Updated:\s*(.+)",
        r"last-modified:\s*(.+)",
        r"Changed:\s*(.+)",
    ],
    "expires": [
        r"Registry Expiry Date:\s*(.+)",
        r"Expiry Date:\s*(.+)",
        r"Expiration Date:\s*(.+)",
        r"expires:\s*(.+)",
        r"Expiry:\s*(.+)",
    ],
    "org": [
        r"Registrant Organization:\s*(.+)",
        r"org:\s*(.+)",
        r"Organization:\s*(.+)",
        r"Registrant:\s*(.+)",
    ],
    "country": [
        r"Registrant Country:\s*(.+)",
        r"country:\s*(.+)",
        r"Country:\s*(.+)",
    ],
}


def _get_tld(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1].lower() if parts else "com"


def _query_whois(domain: str, server: str, timeout: float = 8.0) -> str:
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall(f"{domain}\r\n".encode())
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.decode("utf-8", errors="replace")
    except Exception as e:
        return ""


def _parse_whois(raw: str, report: WhoisReport):
    for field_name, patterns in FIELD_PATTERNS.items():
        for pattern in patterns:
            m = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
            if m:
                value = m.group(1).strip()
                if value and not getattr(report, field_name):
                    setattr(report, field_name, value)
                break

    ns_matches = re.findall(
        r"Name Server:\s*(.+)|nserver:\s*(.+)|nameserver:\s*(.+)",
        raw,
        re.IGNORECASE,
    )
    for groups in ns_matches:
        ns = next((g.strip().lower() for g in groups if g.strip()), None)
        if ns and ns not in report.nameservers:
            report.nameservers.append(ns)

    status_matches = re.findall(
        r"Domain Status:\s*(.+)|status:\s*(.+)",
        raw,
        re.IGNORECASE,
    )
    for groups in status_matches:
        st = next((g.strip() for g in groups if g.strip()), None)
        if st and st not in report.status:
            report.status.append(st.split(" ")[0])


async def _query_asn(ip: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    try:
        raw = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: _query_whois(f" -v {ip}", "whois.cymru.com", timeout=8),
        )
        lines = [l.strip() for l in raw.strip().split("\n") if l.strip() and not l.startswith("AS")]
        if lines:
            parts = [p.strip() for p in lines[0].split("|")]
            if len(parts) >= 5:
                asn    = parts[0].strip()
                cidr   = parts[2].strip()
                asn_org = parts[4].strip()
                return asn, cidr, asn_org
    except Exception:
        pass
    return None, None, None


def _analyze(report: WhoisReport):
    if report.expires:
        try:
            raw_date = report.expires.strip()[:10]
            exp      = datetime.strptime(raw_date, "%Y-%m-%d")
            days     = (exp - datetime.now()).days
            if days < 0:
                report.findings.append(f"[CRITICAL] Domain is EXPIRED since {report.expires}")
            elif days < 30:
                report.findings.append(f"[HIGH] Domain expires in {days} days")
            elif days < 90:
                report.findings.append(f"[MEDIUM] Domain expires in {days} days")
        except Exception:
            pass

    if report.status:
        statuses = " ".join(report.status).lower()
        if "clienttransferprohibited" not in statuses:
            report.findings.append("[MEDIUM] Domain transfer not prohibited — hijacking risk")
        if "clientdeleteprohibited" not in statuses:
            report.findings.append("[LOW] Domain deletion not prohibited")

    if report.asn:
        report.findings.append(f"[INFO] ASN: {report.asn} — {report.asn_org} ({report.cidr})")


def _display(report: WhoisReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.domain}[/bold white]  "
        f"[dim]ip:[/dim] {report.ip or '-'}  "
        f"[dim]asn:[/dim] {report.asn or '-'}  "
        f"[dim]findings:[/dim] {len(report.findings)}",
        title="[bold red]WHOIS Lookup — Summary[/bold red]",
        border_style="red",
    ))

    table = Table(
        show_header=False,
        border_style="dim",
        box=None,
        padding=(0, 2),
    )
    table.add_column("Field",  style="dim",   width=16)
    table.add_column("Value",  style="white")

    rows = [
        ("Registrar",   report.registrar),
        ("Org",         report.org),
        ("Country",     report.country),
        ("Registered",  report.registered),
        ("Updated",     report.updated),
        ("Expires",     report.expires),
        ("ASN",         f"{report.asn} — {report.asn_org}" if report.asn else None),
        ("CIDR",        report.cidr),
        ("IP",          report.ip),
        ("Nameservers", ", ".join(report.nameservers[:4]) if report.nameservers else None),
        ("Status",      ", ".join(report.status[:3]) if report.status else None),
    ]

    for field_name, value in rows:
        if value:
            table.add_row(field_name, value[:80])

    console.print(table)

    if report.findings:
        console.print(f"\n[bold red][!] Findings:[/bold red]")
        for f in report.findings:
            color = "red" if "CRITICAL" in f or "HIGH" in f else "yellow" if "MEDIUM" in f else "dim"
            console.print(f"    [{color}]{f}[/{color}]")

    console.print()


async def _whois_async(domain: str) -> WhoisReport:
    report        = WhoisReport(target=domain, domain=domain)

    try:
        report.ip = socket.gethostbyname(domain)
        console.print(f"[dim]    Resolved: {report.ip}[/dim]")
    except Exception:
        pass

    tld    = _get_tld(domain)
    server = WHOIS_SERVERS.get(tld, "whois.iana.org")
    console.print(f"[dim]    Querying {server}...[/dim]")

    raw = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: _query_whois(domain, server),
    )

    if not raw and server != "whois.iana.org":
        console.print(f"[dim]    Fallback to whois.iana.org...[/dim]")
        raw = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: _query_whois(domain, "whois.iana.org"),
        )

    if raw:
        report.raw = raw[:3000]
        _parse_whois(raw, report)

    if report.ip:
        console.print(f"[dim]    Querying ASN info...[/dim]")
        report.asn, report.cidr, report.asn_org = await _query_asn(report.ip)

    _analyze(report)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_whois_lookup(
    target:    str,
    save_json: Optional[str] = None,
) -> WhoisReport:

    from urllib.parse import urlparse
    parsed = urlparse(target)
    domain = parsed.hostname or target

    console.print(
        f"\n[bold red][*][/bold red] WHOIS Lookup → "
        f"[bold white]{domain}[/bold white]"
    )

    report = asyncio.run(_whois_async(domain))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report