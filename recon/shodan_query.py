import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

@dataclass
class ShodanHost:
    ip:           str
    port:         int
    protocol:     str               = "tcp"
    service:      Optional[str]     = None
    banner:       Optional[str]     = None
    org:          Optional[str]     = None
    country:      Optional[str]     = None
    city:         Optional[str]     = None
    asn:          Optional[str]     = None
    os:           Optional[str]     = None
    vulns:        list[str]         = field(default_factory=list)
    tags:         list[str]         = field(default_factory=list)
    timestamp:    Optional[str]     = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()

@dataclass
class ShodanReport:
    target:       str
    started_at:   str                    = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:  Optional[str]         = None
    total:        int                    = 0
    hosts:        list[ShodanHost]      = field(default_factory=list)
    facets:       dict                  = field(default_factory=dict)
    interesting:  list[ShodanHost]     = field(default_factory=list)
    vulns:        list[str]            = field(default_factory=list)
    errors:       list[str]           = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["hosts"]       = [h.to_dict() for h in self.hosts]
        d["interesting"] = [h.to_dict() for h in self.interesting]
        return d

INTERESTING_PORTS = {
    21, 22, 23, 25, 3306, 5432, 6379, 27017, 9200,
    2375, 2376, 5900, 3389, 11211, 9042, 5984, 7474,
    8500, 9090, 15672, 61616, 50070,
}

INTERESTING_SERVICES = {
    "redis", "mongodb", "elasticsearch", "docker",
    "memcached", "cassandra", "couchdb", "rabbitmq",
    "kafka", "hadoop", "consul", "prometheus",
    "vnc", "rdp", "telnet", "ftp",
}

DORK_TEMPLATES = [
    'hostname:"{domain}"',
    'ssl:"{domain}"',
    'http.title:"{domain}"',
    'http.html:"{domain}"',
    'org:"{domain}"',
    'ssl.cert.subject.cn:"{domain}"',
    'http.favicon.hash:{favicon_hash}',
]

async def _search(
    client:  httpx.AsyncClient,
    query:   str,
    api_key: str,
    page:    int = 1,
) -> Optional[dict]:
    try:
        r = await client.get(
            "https://api.shodan.io/shodan/host/search",
            params={
                "key":   api_key,
                "query": query,
                "page":  str(page),
                "facets": "port,org,country,os",
            },
            timeout=15,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 401:
            console.print("[red][!] Invalid Shodan API key[/red]")
        if r.status_code == 402:
            console.print("[yellow][!] Shodan query credits exhausted[/yellow]")
    except Exception as e:
        pass
    return None

async def _host_info(
    client:  httpx.AsyncClient,
    ip:      str,
    api_key: str,
) -> Optional[dict]:
    try:
        r = await client.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

async def _dns_resolve(
    client:  httpx.AsyncClient,
    domain:  str,
    api_key: str,
) -> list[str]:
    ips = []
    try:
        r = await client.get(
            "https://api.shodan.io/dns/resolve",
            params={"key": api_key, "hostnames": domain},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            ips  = list(data.values())
    except Exception:
        pass
    return ips

async def _reverse_dns(
    client:  httpx.AsyncClient,
    ip:      str,
    api_key: str,
) -> list[str]:
    try:
        r = await client.get(
            "https://api.shodan.io/dns/reverse",
            params={"key": api_key, "ips": ip},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            return data.get(ip, [])
    except Exception:
        pass
    return []

async def _search_free(
    client: httpx.AsyncClient,
    domain: str,
) -> list[ShodanHost]:
    hosts = []
    try:
        r = await client.get(
            f"https://internetdb.shodan.io/{domain}",
            timeout=10,
        )
        if r.status_code == 200:
            data  = r.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            tags  = data.get("tags", [])
            for port in ports:
                hosts.append(ShodanHost(
                    ip=domain,
                    port=port,
                    vulns=vulns,
                    tags=tags,
                ))
    except Exception:
        pass
    return hosts

def _parse_matches(matches: list[dict]) -> list[ShodanHost]:
    hosts = []
    for m in matches:
        host = ShodanHost(
            ip=m.get("ip_str", ""),
            port=m.get("port", 0),
            protocol=m.get("transport", "tcp"),
            service=m.get("product"),
            banner=(m.get("data") or "")[:200],
            org=m.get("org"),
            country=m.get("location", {}).get("country_name"),
            city=m.get("location", {}).get("city"),
            asn=m.get("asn"),
            os=m.get("os"),
            vulns=list((m.get("vulns") or {}).keys()),
            tags=m.get("tags", []),
            timestamp=m.get("timestamp"),
        )
        hosts.append(host)
    return hosts

def _find_interesting(hosts: list[ShodanHost]) -> list[ShodanHost]:
    found = []
    for h in hosts:
        if h.port in INTERESTING_PORTS:
            found.append(h)
        elif h.service and h.service.lower() in INTERESTING_SERVICES:
            found.append(h)
        elif h.vulns:
            found.append(h)
        elif "honeypot" in h.tags or "self-signed" in h.tags:
            found.append(h)
    return found

def _collect_vulns(hosts: list[ShodanHost]) -> list[str]:
    vulns = set()
    for h in hosts:
        vulns.update(h.vulns)
    return sorted(vulns)

def _display(report: ShodanReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]total:[/dim] {report.total}  "
        f"[dim]hosts:[/dim] [green]{len(report.hosts)}[/green]  "
        f"[dim]interesting:[/dim] [yellow]{len(report.interesting)}[/yellow]  "
        f"[dim]vulns:[/dim] [red]{len(report.vulns)}[/red]",
        title="[bold red]Shodan Query — Summary[/bold red]",
        border_style="red",
    ))

    if not report.hosts:
        console.print("[dim]    No results found.[/dim]\n")
        return

    if report.vulns:
        console.print(f"\n[bold red][!] CVEs found:[/bold red]")
        for v in report.vulns:
            console.print(f"    [red]→[/red] {v}")

    if report.facets:
        if "port" in report.facets:
            console.print(f"\n[dim]Top ports:[/dim]")
            for item in report.facets["port"][:8]:
                console.print(f"  [cyan]{item['value']}[/cyan]  [dim]{item['count']}[/dim]")

        if "org" in report.facets:
            console.print(f"\n[dim]Top orgs:[/dim]")
            for item in report.facets["org"][:5]:
                console.print(f"  [white]{item['value']}[/white]  [dim]{item['count']}[/dim]")

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("IP",       width=18, style="cyan")
    table.add_column("Port",     width=7)
    table.add_column("Service",  width=16, style="dim")
    table.add_column("Org",      width=25, style="dim")
    table.add_column("Country",  width=12, style="dim")
    table.add_column("Vulns",    width=8,  style="red")
    table.add_column("Tags",     min_width=15, style="yellow")

    for h in report.hosts[:30]:
        color = "red" if h.vulns else "green" if h.port in INTERESTING_PORTS else "white"
        table.add_row(
            h.ip,
            f"[{color}]{h.port}[/{color}]",
            h.service or "-",
            (h.org or "-")[:25],
            h.country or "-",
            str(len(h.vulns)) if h.vulns else "-",
            ", ".join(h.tags[:2]) if h.tags else "-",
        )

    console.print(table)

    if report.interesting:
        console.print(f"\n[bold red][!] Interesting hosts:[/bold red]")
        for h in report.interesting[:10]:
            console.print(
                f"    [red]→[/red] [cyan]{h.ip}[/cyan]:{h.port} "
                f"[dim]{h.service or ''}[/dim]"
                + (f" [red]CVEs: {', '.join(h.vulns[:3])}[/red]" if h.vulns else "")
            )

    console.print()

async def _shodan_async(
    domain:  str,
    api_key: Optional[str],
    queries: list[str],
) -> ShodanReport:

    report = ShodanReport(target=domain)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        if not api_key:
            console.print("[yellow][!] No API key — using Shodan InternetDB (free)[/yellow]")
            console.print(f"[dim]    Querying internetdb.shodan.io...[/dim]")
            import socket
            try:
                ip    = socket.gethostbyname(domain)
                hosts = await _search_free(client, ip)
                report.hosts       = hosts
                report.total       = len(hosts)
                report.interesting = _find_interesting(hosts)
                report.vulns       = _collect_vulns(hosts)
            except Exception:
                pass
            return report

        console.print(f"[dim]    Resolving {domain}...[/dim]")
        ips = await _dns_resolve(client, domain, api_key)
        if ips:
            console.print(f"[dim]    IPs: {', '.join(ips[:5])}[/dim]")

        for query in queries:
            console.print(f"[dim]    Query: {query}[/dim]")
            data = await _search(client, query, api_key)
            if not data:
                continue

            matches = _parse_matches(data.get("matches", []))
            report.hosts.extend(matches)
            report.total = max(report.total, data.get("total", 0))

            if not report.facets and "facets" in data:
                report.facets = data["facets"]

            for match in matches:
                console.print(
                    f"  [green][+][/green] [cyan]{match.ip}[/cyan]:{match.port} "
                    f"[dim]{match.service or ''}[/dim]"
                    + (f" [red]{', '.join(match.vulns[:2])}[/red]" if match.vulns else "")
                )

            await asyncio.sleep(1)

        seen  = set()
        dedup = []
        for h in report.hosts:
            key = f"{h.ip}:{h.port}"
            if key not in seen:
                seen.add(key)
                dedup.append(h)
        report.hosts       = dedup
        report.interesting = _find_interesting(report.hosts)
        report.vulns       = _collect_vulns(report.hosts)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report

def run_shodan_query(
    target:    str,
    api_key:   Optional[str] = None,
    queries:   Optional[list[str]] = None,
    save_json: Optional[str] = None,
) -> ShodanReport:

    parsed = urlparse(target)
    domain = parsed.hostname or target

    console.print(
        f"\n[bold red][*][/bold red] Shodan Query → "
        f"[bold white]{domain}[/bold white]"
    )

    if not queries:
        queries = [
            f'hostname:"{domain}"',
            f'ssl:"{domain}"',
            f'http.title:"{domain}"',
        ]

    report = asyncio.run(_shodan_async(
        domain=domain,
        api_key=api_key,
        queries=queries,
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