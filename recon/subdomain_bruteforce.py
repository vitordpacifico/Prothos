import asyncio
import socket
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from itertools import islice
from utils.wordlist_loader import load_wordlist
import dns.asyncresolver
import dns.exception
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

@dataclass
class SubdomainResult:
    subdomain:   str
    ip:          list[str]        = field(default_factory=list)
    cname:       Optional[str]    = None
    mx:          list[str]        = field(default_factory=list)
    txt:         list[str]        = field(default_factory=list)
    ns:          list[str]        = field(default_factory=list)
    http_status: Optional[int]    = None
    https_status:Optional[int]    = None
    http_title:  Optional[str]    = None
    cdn:         Optional[str]    = None
    takeover_risk: bool           = False
    takeover_hint: Optional[str]  = None
    wildcard:    bool             = False
    timestamp:   str              = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class BruteforceReport:
    domain:      str
    started_at:  str              = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]    = None
    wordlist:    str              = ""
    total_tested:int              = 0
    found:       list[SubdomainResult] = field(default_factory=list)
    errors:      list[str]        = field(default_factory=list)
    wildcard_detected: bool       = False
    wildcard_ip: Optional[str]    = None

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["found"] = [s.to_dict() for s in self.found]
        return d

TAKEOVER_SIGNATURES: list[tuple[str, str]] = [
    ("amazonaws.com",           "AWS S3 / Elastic Beanstalk"),
    ("cloudfront.net",          "AWS CloudFront"),
    ("elasticbeanstalk.com",    "AWS Elastic Beanstalk"),
    ("s3.amazonaws.com",        "AWS S3"),
    ("azurewebsites.net",       "Azure Web Apps"),
    ("azure-api.net",           "Azure API Management"),
    ("cloudapp.azure.com",      "Azure Cloud App"),
    ("trafficmanager.net",      "Azure Traffic Manager"),
    ("blob.core.windows.net",   "Azure Blob Storage"),
    ("github.io",               "GitHub Pages"),
    ("herokuapp.com",           "Heroku"),
    ("herokudns.com",           "Heroku DNS"),
    ("fastly.net",              "Fastly"),
    ("pantheonsite.io",         "Pantheon"),
    ("domains.tumblr.com",      "Tumblr"),
    ("helpscoutdocs.com",       "HelpScout"),
    ("ghost.io",                "Ghost"),
    ("netlify.app",             "Netlify"),
    ("netlify.com",             "Netlify"),
    ("vercel.app",              "Vercel"),
    ("fly.dev",                 "Fly.io"),
    ("render.com",              "Render"),
    ("readthedocs.io",          "ReadTheDocs"),
    ("zendesk.com",             "Zendesk"),
    ("freshdesk.com",           "Freshdesk"),
    ("helpjuice.com",           "HelpJuice"),
    ("bitbucket.io",            "Bitbucket"),
    ("cargo.site",              "Cargo"),
    ("feedpress.me",            "FeedPress"),
    ("myshopify.com",           "Shopify"),
    ("squarespace.com",         "Squarespace"),
    ("webflow.io",              "Webflow"),
    ("surge.sh",                "Surge.sh"),
    ("hubspotpagebuilder.com",  "HubSpot"),
    ("kinsta.cloud",            "Kinsta"),
]

CDN_HINTS: list[tuple[str, str]] = [
    ("cloudflare",  "Cloudflare"),
    ("akamai",      "Akamai"),
    ("fastly",      "Fastly"),
    ("cloudfront",  "AWS CloudFront"),
    ("azure",       "Azure"),
    ("google",      "Google"),
    ("vercel",      "Vercel"),
    ("netlify",     "Netlify"),
]

async def _detect_wildcard(domain: str) -> tuple[bool, Optional[str]]:
    """
    Resolve um subdomínio aleatório improvável.
    Se resolver → wildcard DNS ativo → resultados do bruteforce serão falsos positivos.
    """
    canary = f"prothos-canary-99zx7q.{domain}"
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        ans = await resolver.resolve(canary, "A")
        ip  = ans[0].to_text()
        return True, ip
    except Exception:
        return False, None

async def _resolve_all(
    subdomain: str,
    resolver: dns.asyncresolver.Resolver,
    http_probe: bool = True,
) -> Optional[SubdomainResult]:
    """Resolve A, CNAME, MX, TXT, NS e opcionalmente faz HTTP probe."""

    result = SubdomainResult(subdomain=subdomain)

    try:
        ans = await resolver.resolve(subdomain, "A")
        result.ip = [r.to_text() for r in ans]
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        pass
    except Exception:
        pass

    try:
        ans = await resolver.resolve(subdomain, "CNAME")
        result.cname = ans[0].to_text().rstrip(".")
    except Exception:
        pass

    try:
        ans = await resolver.resolve(subdomain, "MX")
        result.mx = [r.exchange.to_text().rstrip(".") for r in ans]
    except Exception:
        pass

    try:
        ans = await resolver.resolve(subdomain, "TXT")
        result.txt = [b.decode() for r in ans for b in r.strings]
    except Exception:
        pass

    cname_check = result.cname or ""
    for pattern, service in TAKEOVER_SIGNATURES:
        if pattern in cname_check:
            result.takeover_risk = True
            result.takeover_hint = service
            break

    for hint, name in CDN_HINTS:
        if hint in cname_check:
            result.cdn = name
            break

    if http_probe and (result.ip or result.cname):
        result.http_status, result.https_status, result.http_title = await _http_probe(subdomain)

    return result if (result.ip or result.cname) else None

async def _http_probe(subdomain: str) -> tuple[Optional[int], Optional[int], Optional[str]]:
    """Testa HTTP e HTTPS, extrai status code e <title>."""
    http_status = https_status = None
    title = None

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=6,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{subdomain}", timeout=6)
                if scheme == "https":
                    https_status = r.status_code
                else:
                    http_status = r.status_code
                if title is None:
                    import re
                    m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = m.group(1).strip()[:80]
            except Exception:
                pass

    return http_status, https_status, title

def _chunked(iterable, size):
    it = iter(iterable)
    while chunk := list(islice(it, size)):
        yield chunk


async def _bruteforce_async(
    domain:      str,
    wordlist:    list[str],
    concurrency: int = 100,
    http_probe:  bool = True,
    resolvers:   list[str] = None,
) -> BruteforceReport:

    report = BruteforceReport(domain=domain, wordlist=f"{len(wordlist)} words")

    is_wildcard, wc_ip = await _detect_wildcard(domain)
    report.wildcard_detected = is_wildcard
    report.wildcard_ip       = wc_ip

    if is_wildcard:
        console.print(f"[bold yellow][!] Wildcard DNS detected ({wc_ip}). "
                      f"Results may include false positives.[/bold yellow]")

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout  = 3
    resolver.lifetime = 5
    if resolvers:
        resolver.nameservers = resolvers
    else:
        resolver.nameservers = [
            "1.1.1.1",
            "8.8.8.8",
            "9.9.9.9",
            "208.67.222.222",
        ]

    subdomains = [f"{word}.{domain}" for word in wordlist]
    report.total_tested = len(subdomains)

    sem = asyncio.Semaphore(concurrency)

    async def bounded_resolve(sub):
        async with sem:
            return await _resolve_all(sub, resolver, http_probe=http_probe)

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=35, style="red", complete_style="green"),
        TextColumn("[green]{task.completed}[/green]/[white]{task.total}[/white]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"Bruteforcing [bold red]{domain}[/bold red]",
            total=len(subdomains)
        )

        for chunk in _chunked(subdomains, concurrency * 2):
            results = await asyncio.gather(*[bounded_resolve(s) for s in chunk])
            for res in results:
                if res:
                    res.wildcard = is_wildcard
                    report.found.append(res)
                    _print_found(res)
            progress.advance(task, len(chunk))

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report

def _print_found(r: SubdomainResult):
    ip_str   = ", ".join(r.ip[:3]) if r.ip else r.cname or "?"
    takeover = f" [bold red blink][TAKEOVER? {r.takeover_hint}][/bold red blink]" if r.takeover_risk else ""
    cdn_str  = f" [dim]({r.cdn})[/dim]" if r.cdn else ""
    http_str = ""
    if r.https_status: http_str += f" [cyan]HTTPS:{r.https_status}[/cyan]"
    if r.http_status:  http_str += f" [dim]HTTP:{r.http_status}[/dim]"
    title    = f" [dim italic]{r.http_title}[/dim italic]" if r.http_title else ""
    console.print(f"  [green]✓[/green] [bold white]{r.subdomain}[/bold white] → [yellow]{ip_str}[/yellow]{cdn_str}{http_str}{title}{takeover}")


def _display_summary(report: BruteforceReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.domain}[/bold white]  "
        f"[dim]tested:[/dim] {report.total_tested}  "
        f"[dim]found:[/dim] [green]{len(report.found)}[/green]  "
        f"[dim]duration:[/dim] {report.started_at} → {report.finished_at}",
        title="[bold red]Subdomain Bruteforce — Summary[/bold red]",
        border_style="red",
    ))

    if not report.found:
        console.print("[dim]  No subdomains found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Subdomain",   style="bold white",  min_width=30)
    table.add_column("IP / CNAME",  style="yellow",      min_width=20)
    table.add_column("HTTP",        style="cyan",        width=6)
    table.add_column("HTTPS",       style="cyan",        width=7)
    table.add_column("CDN",         style="dim",         width=15)
    table.add_column("Takeover",    style="bold red",    width=20)
    table.add_column("Title",       style="dim italic",  min_width=20)

    for r in sorted(report.found, key=lambda x: x.subdomain):
        ip     = ", ".join(r.ip[:2]) if r.ip else r.cname or "?"
        http   = str(r.http_status)  if r.http_status  else "-"
        https  = str(r.https_status) if r.https_status else "-"
        cdn    = r.cdn               or "-"
        risk   = f"⚠ {r.takeover_hint}" if r.takeover_risk else "-"
        title  = (r.http_title or "")[:35]
        table.add_row(r.subdomain, ip, http, https, cdn, risk, title)

    console.print(table)

    takeovers = [r for r in report.found if r.takeover_risk]
    if takeovers:
        console.print(f"\n[bold red][!] POTENTIAL SUBDOMAIN TAKEOVERS: {len(takeovers)}[/bold red]")
        for r in takeovers:
            console.print(f"    [red]→[/red] [bold]{r.subdomain}[/bold]  CNAME: {r.cname}  Service: {r.takeover_hint}")

    console.print()

def run_subdomain_bruteforce(
    domain:      str,
    wordlist_path: str | Path = "wordlists/subdomains.txt",
    concurrency: int  = 100,
    http_probe:  bool = True,
    resolvers:   list[str] = None,
    save_json:   Optional[str] = None,
) -> BruteforceReport:

    from utils.wordlist import load_wordlist

    console.print(f"\n[bold red][*][/bold red] Subdomain bruteforce → [bold white]{domain}[/bold white]")

    try:
        wordlist = load_wordlist(wordlist_path)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red][!] {e}[/red]")
        return BruteforceReport(domain=domain)

    console.print(f"[dim]    Wordlist: {wordlist_path} ({len(wordlist)} words)  "
                  f"Concurrency: {concurrency}  HTTP probe: {http_probe}[/dim]\n")

    report = asyncio.run(_bruteforce_async(
        domain=domain,
        wordlist=wordlist,
        concurrency=concurrency,
        http_probe=http_probe,
        resolvers=resolvers,
    ))

    _display_summary(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save JSON: {e}[/red]")

    return report