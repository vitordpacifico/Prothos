import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import dns.asyncresolver
import dns.resolver
import dns.zone
import dns.query
import dns.exception
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

@dataclass
class DNSRecord:
    record_type: str
    value:       str
    ttl:         Optional[int] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class DNSReport:
    domain:      str
    started_at:  str                      = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None

    a:           list[DNSRecord]          = field(default_factory=list)
    aaaa:        list[DNSRecord]          = field(default_factory=list)
    mx:          list[DNSRecord]          = field(default_factory=list)
    ns:          list[DNSRecord]          = field(default_factory=list)
    txt:         list[DNSRecord]          = field(default_factory=list)
    cname:       list[DNSRecord]          = field(default_factory=list)
    soa:         list[DNSRecord]          = field(default_factory=list)
    ptr:         list[DNSRecord]          = field(default_factory=list)
    srv:         list[DNSRecord]          = field(default_factory=list)
    caa:         list[DNSRecord]          = field(default_factory=list)

    spf:         Optional[str]            = None
    dmarc:       Optional[str]            = None
    dkim_selectors: list[str]             = field(default_factory=list)

    zone_transfer: bool                   = False
    zone_transfer_data: list[str]         = field(default_factory=list)

    findings:    list[str]                = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    @property
    def all_records(self) -> list[DNSRecord]:
        records = []
        for rtype in ("a", "aaaa", "mx", "ns", "txt", "cname", "soa", "ptr", "srv", "caa"):
            records.extend(getattr(self, rtype))
        return records

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        for rtype in ("a", "aaaa", "mx", "ns", "txt", "cname", "soa", "ptr", "srv", "caa"):
            d[rtype] = [r.to_dict() for r in getattr(self, rtype)]
        return d

RESOLVERS = [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    "208.67.222.222",
]

DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "k2",
    "selector1", "selector2", "smtp", "email", "s1", "s2",
    "mandrill", "sendgrid", "mailgun", "amazonses",
]

async def _query(
    resolver: dns.asyncresolver.Resolver,
    domain:   str,
    rtype:    str,
) -> list[DNSRecord]:
    records = []
    try:
        answers = await resolver.resolve(domain, rtype)
        for rdata in answers:
            records.append(DNSRecord(
                record_type=rtype,
                value=str(rdata).rstrip("."),
                ttl=answers.rrset.ttl if answers.rrset else None,
            ))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    except Exception as e:
        pass
    return records


async def _check_dkim(
    resolver:  dns.asyncresolver.Resolver,
    domain:    str,
    selector:  str,
) -> bool:
    """Testa se um seletor DKIM existe."""
    try:
        target = f"{selector}._domainkey.{domain}"
        await resolver.resolve(target, "TXT")
        return True
    except Exception:
        return False


def _try_zone_transfer(domain: str, nameservers: list[str]) -> list[str]:
    results = []
    for ns in nameservers:
        try:
            ns_ip = dns.resolver.resolve(ns, "A")[0].to_text()
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            for name, node in z.nodes.items():
                results.append(f"{name}.{domain}")
        except Exception:
            pass
    return results


def _analyze_txt(records: list[DNSRecord]) -> tuple[Optional[str], Optional[str]]:
    spf   = None
    dmarc = None
    for r in records:
        v = r.value.lower()
        if v.startswith("v=spf1"):
            spf = r.value
        if "v=dmarc1" in v:
            dmarc = r.value
    return spf, dmarc


def _analyze_findings(report: DNSReport):

    # SPF
    if not report.spf:
        report.findings.append("[MEDIUM] No SPF record found — email spoofing possible")
    elif "+all" in report.spf:
        report.findings.append("[HIGH] SPF uses '+all' — allows any server to send email")
    elif "~all" in report.spf:
        report.findings.append("[LOW] SPF uses '~all' (softfail) — consider '-all'")

    # DMARC
    if not report.dmarc:
        report.findings.append("[MEDIUM] No DMARC record found — no email auth policy")
    elif "p=none" in (report.dmarc or "").lower():
        report.findings.append("[LOW] DMARC policy is 'none' — not enforcing")
    elif "p=quarantine" in (report.dmarc or "").lower():
        report.findings.append("[INFO] DMARC policy is 'quarantine'")

    # Zone transfer
    if report.zone_transfer:
        report.findings.append(
            f"[CRITICAL] Zone transfer successful — "
            f"{len(report.zone_transfer_data)} records exposed"
        )

    # Nameservers
    if len(report.ns) == 1:
        report.findings.append("[LOW] Single nameserver — no redundancy")

    # DKIM
    if not report.dkim_selectors:
        report.findings.append("[INFO] No common DKIM selectors found")

    # MX
    if not report.mx:
        report.findings.append("[INFO] No MX records — domain may not receive email")

    # IPv6
    if not report.aaaa:
        report.findings.append("[INFO] No AAAA records — no IPv6 support")

def _display(report: DNSReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.domain}[/bold white]  "
        f"[dim]records:[/dim] {len(report.all_records)}  "
        f"[dim]findings:[/dim] {len(report.findings)}  "
        f"[dim]zone transfer:[/dim] {'[red]YES[/red]' if report.zone_transfer else '[dim]no[/dim]'}",
        title="[bold red]DNS Recon — Summary[/bold red]",
        border_style="red",
    ))

    table = Table(
        show_header=True,
        header_style="bold red",
        border_style="dim",
    )
    table.add_column("Type",  style="red",   width=8)
    table.add_column("Value", style="white", min_width=40)
    table.add_column("TTL",   style="dim",   width=8)

    for rtype in ("a", "aaaa", "ns", "mx", "cname", "soa", "txt", "srv", "caa", "ptr"):
        for r in getattr(report, rtype):
            table.add_row(
                r.record_type,
                r.value[:80],
                str(r.ttl) if r.ttl else "-",
            )

    console.print(table)

    if report.spf:
        console.print(f"\n[dim]SPF:[/dim]   {report.spf}")
    if report.dmarc:
        console.print(f"[dim]DMARC:[/dim] {report.dmarc}")
    if report.dkim_selectors:
        console.print(f"[dim]DKIM:[/dim]  {', '.join(report.dkim_selectors)}")

    if report.zone_transfer_data:
        console.print(f"\n[bold red][!] Zone Transfer Data ({len(report.zone_transfer_data)} records):[/bold red]")
        for record in report.zone_transfer_data[:20]:
            console.print(f"    [red]→[/red] {record}")
        if len(report.zone_transfer_data) > 20:
            console.print(f"    [dim]... and {len(report.zone_transfer_data) - 20} more[/dim]")

    if report.findings:
        console.print(f"\n[bold red][!] Findings:[/bold red]")
        for f in report.findings:
            color = "red" if "CRITICAL" in f or "HIGH" in f else "yellow" if "MEDIUM" in f else "dim"
            console.print(f"    [{color}]{f}[/{color}]")

    console.print()

async def _dns_recon_async(
    domain:        str,
    check_dkim:    bool = True,
    zone_transfer: bool = True,
) -> DNSReport:

    report   = DNSReport(domain=domain)
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = RESOLVERS
    resolver.timeout     = 5
    resolver.lifetime    = 10

    console.print(f"[dim]    Querying DNS records for {domain}...[/dim]")

    results = await asyncio.gather(
        _query(resolver, domain, "A"),
        _query(resolver, domain, "AAAA"),
        _query(resolver, domain, "MX"),
        _query(resolver, domain, "NS"),
        _query(resolver, domain, "TXT"),
        _query(resolver, domain, "CNAME"),
        _query(resolver, domain, "SOA"),
        _query(resolver, domain, "CAA"),
        _query(resolver, domain, "SRV"),
        return_exceptions=True,
    )

    record_types = ("a", "aaaa", "mx", "ns", "txt", "cname", "soa", "caa", "srv")
    for rtype, result in zip(record_types, results):
        if isinstance(result, list):
            setattr(report, rtype, result)

    report.spf, report.dmarc = _analyze_txt(report.txt)

    dmarc_records = await _query(resolver, f"_dmarc.{domain}", "TXT")
    if dmarc_records and not report.dmarc:
        report.dmarc = dmarc_records[0].value

    if check_dkim:
        console.print(f"[dim]    Checking {len(DKIM_SELECTORS)} DKIM selectors...[/dim]")
        dkim_tasks = [_check_dkim(resolver, domain, sel) for sel in DKIM_SELECTORS]
        dkim_results = await asyncio.gather(*dkim_tasks, return_exceptions=True)
        report.dkim_selectors = [
            sel for sel, found in zip(DKIM_SELECTORS, dkim_results)
            if found is True
        ]

    if zone_transfer and report.ns:
        console.print(f"[dim]    Attempting zone transfer on {len(report.ns)} nameservers...[/dim]")
        ns_values = [r.value for r in report.ns]
        zt_data   = _try_zone_transfer(domain, ns_values)
        if zt_data:
            report.zone_transfer      = True
            report.zone_transfer_data = zt_data

    _analyze_findings(report)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_dns_recon(
    domain:        str,
    check_dkim:    bool         = True,
    zone_transfer: bool         = True,
    save_json:     Optional[str]= None,
) -> DNSReport:
    from urllib.parse import urlparse
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    console.print(f"\n[bold red][*][/bold red] DNS Recon → [bold white]{domain}[/bold white]")

    report = asyncio.run(_dns_recon_async(
        domain=domain,
        check_dkim=check_dkim,
        zone_transfer=zone_transfer,
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