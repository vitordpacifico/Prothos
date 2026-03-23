import asyncio
import json
import re
import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class CertResult:
    domain:       str
    source:       str
    first_seen:   Optional[str] = None
    last_seen:    Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class CertInfo:
    subject:      Optional[str]       = None
    issuer:       Optional[str]       = None
    valid_from:   Optional[str]       = None
    valid_to:     Optional[str]       = None
    serial:       Optional[str]       = None
    san:          list[str]           = field(default_factory=list)
    expired:      bool                = False
    self_signed:  bool                = False
    wildcard:     bool                = False

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class CertReport:
    target:       str
    started_at:   str                     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:  Optional[str]          = None
    cert_info:    Optional[CertInfo]     = None
    subdomains:   list[CertResult]       = field(default_factory=list)
    unique:       list[str]              = field(default_factory=list)
    interesting:  list[str]             = field(default_factory=list)
    errors:       list[str]             = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["cert_info"]  = self.cert_info.to_dict() if self.cert_info else None
        d["subdomains"] = [r.to_dict() for r in self.subdomains]
        return d


INTERESTING_KEYWORDS = {
    "admin", "api", "internal", "intranet", "dev", "staging",
    "test", "debug", "private", "secret", "backend", "vpn",
    "mail", "smtp", "ftp", "ssh", "git", "jenkins", "jira",
    "kibana", "grafana", "prometheus", "consul", "vault",
    "auth", "sso", "login", "portal", "dashboard", "panel",
    "legacy", "old", "beta", "alpha", "preprod", "prod",
}


async def _fetch_crtsh(
    client: httpx.AsyncClient,
    domain: str,
) -> list[CertResult]:
    results = []
    try:
        r = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=20,
        )
        if r.status_code != 200:
            return results

        data = r.json()
        for entry in data:
            names = entry.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip().lower()
                if name and domain in name:
                    results.append(CertResult(
                        domain=name,
                        source="crt.sh",
                        first_seen=entry.get("not_before"),
                        last_seen=entry.get("not_after"),
                    ))
    except Exception as e:
        pass
    return results


async def _fetch_certspotter(
    client: httpx.AsyncClient,
    domain: str,
) -> list[CertResult]:
    results = []
    try:
        r = await client.get(
            f"https://api.certspotter.com/v1/issuances",
            params={
                "domain":             domain,
                "include_subdomains": "true",
                "expand":             "dns_names",
            },
            timeout=20,
        )
        if r.status_code != 200:
            return results

        data = r.json()
        for entry in data:
            for name in entry.get("dns_names", []):
                name = name.strip().lower()
                if domain in name:
                    results.append(CertResult(
                        domain=name,
                        source="certspotter",
                        first_seen=entry.get("not_before"),
                        last_seen=entry.get("not_after"),
                    ))
    except Exception:
        pass
    return results


async def _fetch_facebook_ct(
    client: httpx.AsyncClient,
    domain: str,
) -> list[CertResult]:
    results = []
    try:
        r = await client.get(
            "https://developers.facebook.com/tools/ct/",
            params={"query": domain},
            timeout=15,
        )
        matches = re.findall(
            r'[\w.-]+\.' + re.escape(domain),
            r.text,
            re.IGNORECASE,
        )
        for name in set(matches):
            results.append(CertResult(
                domain=name.lower(),
                source="facebook-ct",
            ))
    except Exception:
        pass
    return results


def _get_live_cert(domain: str) -> Optional[CertInfo]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))

                san = []
                for ext in cert.get("subjectAltName", []):
                    if ext[0] == "DNS":
                        san.append(ext[1].lower())

                valid_from = cert.get("notBefore")
                valid_to   = cert.get("notAfter")

                expired     = False
                self_signed = subject.get("commonName") == issuer.get("commonName")
                wildcard    = any("*" in s for s in san)

                if valid_to:
                    try:
                        exp = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z")
                        expired = exp < datetime.now()
                    except Exception:
                        pass

                return CertInfo(
                    subject=subject.get("commonName"),
                    issuer=issuer.get("organizationName") or issuer.get("commonName"),
                    valid_from=valid_from,
                    valid_to=valid_to,
                    san=san,
                    expired=expired,
                    self_signed=self_signed,
                    wildcard=wildcard,
                )
    except Exception:
        return None


def _deduplicate(results: list[CertResult]) -> list[str]:
    seen = set()
    unique = []
    for r in results:
        name = r.domain.lstrip("*.")
        if name and name not in seen:
            seen.add(name)
            unique.append(name)
    return sorted(unique)


def _find_interesting(subdomains: list[str]) -> list[str]:
    found = []
    for sub in subdomains:
        parts = sub.split(".")
        for part in parts:
            if part.lower() in INTERESTING_KEYWORDS:
                found.append(sub)
                break
    return found


def _display(report: CertReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]subdomains:[/dim] {len(report.unique)}  "
        f"[dim]interesting:[/dim] [yellow]{len(report.interesting)}[/yellow]",
        title="[bold red]Certificate Enum — Summary[/bold red]",
        border_style="red",
    ))

    if report.cert_info:
        ci = report.cert_info
        console.print(f"\n[dim]Live Certificate:[/dim]")
        console.print(f"  [dim]Subject:[/dim]  {ci.subject}")
        console.print(f"  [dim]Issuer:[/dim]   {ci.issuer}")
        console.print(f"  [dim]Valid to:[/dim] {ci.valid_to}")
        console.print(f"  [dim]SANs:[/dim]     {', '.join(ci.san[:5])}" + (f" +{len(ci.san)-5} more" if len(ci.san) > 5 else ""))

        if ci.expired:
            console.print(f"  [bold red][!] Certificate is EXPIRED[/bold red]")
        if ci.self_signed:
            console.print(f"  [yellow][!] Self-signed certificate[/yellow]")
        if ci.wildcard:
            console.print(f"  [dim][*] Wildcard certificate[/dim]")

    if report.interesting:
        console.print(f"\n[bold red][!] Interesting subdomains:[/bold red]")
        for sub in report.interesting:
            console.print(f"    [red]→[/red] [cyan]{sub}[/cyan]")

    if report.unique:
        console.print(f"\n[dim]All subdomains ({len(report.unique)}):[/dim]")
        table = Table(
            show_header=True,
            header_style="bold red",
            border_style="dim",
        )
        table.add_column("Subdomain", min_width=45, style="cyan")
        table.add_column("Source",    width=14, style="dim")

        seen_names = {r.domain.lstrip("*."): r.source for r in report.subdomains}
        for sub in report.unique[:60]:
            table.add_row(sub, seen_names.get(sub, "-"))

        console.print(table)

        if len(report.unique) > 60:
            console.print(f"[dim]    ... and {len(report.unique) - 60} more[/dim]")

    console.print()


async def _cert_async(domain: str) -> CertReport:
    report = CertReport(target=domain)

    console.print(f"[dim]    Fetching live certificate...[/dim]")
    report.cert_info = _get_live_cert(domain)
    if report.cert_info:
        console.print(f"[dim]    SANs in live cert: {len(report.cert_info.san)}[/dim]")
        for san in report.cert_info.san:
            report.subdomains.append(CertResult(
                domain=san,
                source="live-cert",
            ))

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        console.print(f"[dim]    Querying crt.sh...[/dim]")
        crtsh = await _fetch_crtsh(client, domain)
        report.subdomains.extend(crtsh)
        console.print(f"[dim]    crt.sh: {len(crtsh)} entries[/dim]")

        console.print(f"[dim]    Querying Certspotter...[/dim]")
        certspotter = await _fetch_certspotter(client, domain)
        report.subdomains.extend(certspotter)
        console.print(f"[dim]    Certspotter: {len(certspotter)} entries[/dim]")

    report.unique      = _deduplicate(report.subdomains)
    report.interesting = _find_interesting(report.unique)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_certificate_enum(
    target:    str,
    save_json: Optional[str] = None,
) -> CertReport:

    from urllib.parse import urlparse
    parsed = urlparse(target)
    domain = parsed.hostname or target

    console.print(
        f"\n[bold red][*][/bold red] Certificate Enum → "
        f"[bold white]{domain}[/bold white]"
    )

    report = asyncio.run(_cert_async(domain))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report