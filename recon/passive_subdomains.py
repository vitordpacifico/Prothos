import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

@dataclass
class PassiveSubdomainResult:
    subdomain:  str
    sources:    list[str] = field(default_factory=list)
    ip:         list[str] = field(default_factory=list)
    http_status:Optional[int] = None
    https_status:Optional[int] = None
    http_title: Optional[str] = None
    timestamp:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class PassiveScanReport:
    domain:      str
    started_at:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    found:       list[PassiveSubdomainResult] = field(default_factory=list)
    by_source:   dict[str, int] = field(default_factory=dict)
    errors:      list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["found"] = [s.to_dict() for s in self.found]
        return d

async def _source_crtsh(domain: str, client: httpx.AsyncClient) -> set[str]:
    """crt.sh — certificate transparency logs. Maior base de dados de certs."""
    found = set()
    try:
        r = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20,
        )
        if r.status_code != 200:
            return found
        for entry in r.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(domain) and _valid_subdomain(name):
                    found.add(name)
    except Exception:
        pass
    return found


async def _source_alienvault(domain: str, client: httpx.AsyncClient) -> set[str]:
    """AlienVault OTX — threat intelligence, rico em subdomínios históricos."""
    found = set()
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=15,
        )
        if r.status_code != 200:
            return found
        for entry in r.json().get("passive_dns", []):
            hostname = entry.get("hostname", "").strip().lstrip("*.")
            if hostname.endswith(domain) and _valid_subdomain(hostname):
                found.add(hostname)
    except Exception:
        pass
    return found


async def _source_hackertarget(domain: str, client: httpx.AsyncClient) -> set[str]:
    """HackerTarget — free API, retorna subdomínios em texto plano."""
    found = set()
    try:
        r = await client.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15,
        )
        if r.status_code != 200 or "error" in r.text.lower():
            return found
        for line in r.text.strip().splitlines():
            parts = line.split(",")
            if parts:
                sub = parts[0].strip().lstrip("*.")
                if sub.endswith(domain) and _valid_subdomain(sub):
                    found.add(sub)
    except Exception:
        pass
    return found


async def _source_urlscan(domain: str, client: httpx.AsyncClient) -> set[str]:
    """urlscan.io — scans públicos revelam subdomínios visitados."""
    found = set()
    try:
        r = await client.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
        )
        if r.status_code != 200:
            return found
        for result in r.json().get("results", []):
            page = result.get("page", {})
            for field in ("domain", "apexDomain"):
                val = page.get(field, "").strip()
                if val.endswith(domain) and _valid_subdomain(val):
                    found.add(val)
    except Exception:
        pass
    return found


async def _source_rapiddns(domain: str, client: httpx.AsyncClient) -> set[str]:
    """RapidDNS — scraping HTML, boa cobertura de subdomínios históricos."""
    found = set()
    try:
        r = await client.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
        )
        if r.status_code != 200:
            return found
        matches = re.findall(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>', r.text)
        for m in matches:
            sub = m.strip().lstrip("*.")
            if _valid_subdomain(sub):
                found.add(sub)
    except Exception:
        pass
    return found


async def _source_webarchive(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Wayback Machine CDX — URLs arquivadas revelam subdomínios históricos."""
    found = set()
    try:
        r = await client.get(
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=500",
            timeout=20,
        )
        if r.status_code != 200:
            return found
        for row in r.json()[1:]:
            url = row[0] if row else ""
            m = re.match(r"https?://([a-zA-Z0-9._-]+)", url)
            if m:
                sub = m.group(1).lstrip("*.")
                if sub.endswith(domain) and _valid_subdomain(sub):
                    found.add(sub)
    except Exception:
        pass
    return found


async def _source_threatcrowd(domain: str, client: httpx.AsyncClient) -> set[str]:
    """ThreatCrowd — threat intel, subdomínios associados a IOCs."""
    found = set()
    try:
        r = await client.get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            timeout=10,
        )
        if r.status_code != 200:
            return found
        for sub in r.json().get("subdomains", []):
            sub = sub.strip().lstrip("*.")
            if sub.endswith(domain) and _valid_subdomain(sub):
                found.add(sub)
    except Exception:
        pass
    return found


_SUBDOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$')

def _valid_subdomain(sub: str) -> bool:
    """Filtra wildcards, IPs, strings vazias e subdomínios malformados."""
    if not sub or len(sub) > 253:
        return False
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', sub):  # é IP
        return False
    if "*" in sub or " " in sub:
        return False
    return bool(_SUBDOMAIN_RE.match(sub))

async def _http_probe(subdomain: str, client: httpx.AsyncClient) -> tuple[Optional[int], Optional[int], Optional[str]]:
    http_status = https_status = None
    title = None
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{subdomain}", timeout=6)
            if scheme == "https":
                https_status = r.status_code
            else:
                http_status = r.status_code
            if title is None:
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                if m:
                    title = m.group(1).strip()[:80]
        except Exception:
            pass
    return http_status, https_status, title

SOURCES = {
    "crt.sh":       _source_crtsh,
    "AlienVault":   _source_alienvault,
    "HackerTarget": _source_hackertarget,
    "urlscan.io":   _source_urlscan,
    "RapidDNS":     _source_rapiddns,
    "Wayback":      _source_webarchive,
    "ThreatCrowd":  _source_threatcrowd,
}


async def _passive_scan_async(
    domain:     str,
    http_probe: bool = True,
) -> PassiveScanReport:

    report = PassiveScanReport(domain=domain)
    subdomain_sources: dict[str, set[str]] = {}

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
        timeout=20,
    ) as client:

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Querying passive sources...", total=len(SOURCES))

            async def run_source(name, fn):
                result = await fn(domain, client)
                progress.advance(task, 1)
                progress.update(task, description=f"[dim]{name}[/dim] → [green]{len(result)}[/green] found")
                return name, result

            tasks = [run_source(name, fn) for name, fn in SOURCES.items()]
            results = await asyncio.gather(*tasks)

        for source_name, subs in results:
            report.by_source[source_name] = len(subs)
            for sub in subs:
                if sub not in subdomain_sources:
                    subdomain_sources[sub] = set()
                subdomain_sources[sub].add(source_name)

        if http_probe and subdomain_sources:
            console.print(f"[dim]    Probing {len(subdomain_sources)} subdomains...[/dim]")

            sem = asyncio.Semaphore(50)

            async def probe(sub, sources):
                async with sem:
                    hs, hss, title = await _http_probe(sub, client)
                    return PassiveSubdomainResult(
                        subdomain=sub,
                        sources=sorted(sources),
                        http_status=hs,
                        https_status=hss,
                        http_title=title,
                    )

            probe_tasks = [probe(sub, srcs) for sub, srcs in subdomain_sources.items()]
            report.found = await asyncio.gather(*probe_tasks)
        else:
            report.found = [
                PassiveSubdomainResult(subdomain=sub, sources=sorted(srcs))
                for sub, srcs in subdomain_sources.items()
            ]

    report.found.sort(key=lambda x: x.subdomain)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report

def _print_found(r: PassiveSubdomainResult):
    sources = f"[dim]({', '.join(r.sources)})[/dim]"
    http_str = ""
    if r.https_status: http_str += f" [cyan]HTTPS:{r.https_status}[/cyan]"
    if r.http_status:  http_str += f" [dim]HTTP:{r.http_status}[/dim]"
    title = f" [dim italic]{r.http_title}[/dim italic]" if r.http_title else ""
    console.print(f"  [green]✓[/green] [bold white]{r.subdomain}[/bold white] {sources}{http_str}{title}")


def _display_summary(report: PassiveScanReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.domain}[/bold white]  "
        f"[dim]found:[/dim] [green]{len(report.found)}[/green] unique subdomains  "
        f"[dim]sources:[/dim] {len(SOURCES)}",
        title="[bold red]Passive Subdomain Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.found:
        console.print("[dim]  No subdomains found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Subdomain",  style="bold white",  min_width=30)
    table.add_column("Sources",    style="dim",         min_width=20)
    table.add_column("HTTP",       style="cyan",        width=6)
    table.add_column("HTTPS",      style="cyan",        width=7)
    table.add_column("Title",      style="dim italic",  min_width=25)

    for r in report.found:
        http  = str(r.http_status)  if r.http_status  else "-"
        https = str(r.https_status) if r.https_status else "-"
        title = (r.http_title or "")[:40]
        table.add_row(r.subdomain, ", ".join(r.sources), http, https, title)

    console.print(table)

    src_table = Table(show_header=True, header_style="bold yellow", border_style="dim")
    src_table.add_column("Source",  style="bold cyan", width=20)
    src_table.add_column("Found",   style="green",     width=8)
    for src, count in sorted(report.by_source.items(), key=lambda x: -x[1]):
        src_table.add_row(src, str(count))
    console.print(src_table)
    console.print()

def run_passive_subdomain_scan(
    domain:     str,
    http_probe: bool = True,
    save_json:  Optional[str] = None,
) -> PassiveScanReport:

    console.print(f"\n[bold red][*][/bold red] Passive scan → [bold white]{domain}[/bold white]")
    console.print(f"[dim]    Sources: {', '.join(SOURCES.keys())}[/dim]\n")

    report = asyncio.run(_passive_scan_async(domain=domain, http_probe=http_probe))

    for r in report.found:
        _print_found(r)

    _display_summary(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save JSON: {e}[/red]")

    return report