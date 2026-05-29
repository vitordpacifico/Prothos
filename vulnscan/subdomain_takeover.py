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
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

try:
    import dns.asyncresolver
    import dns.resolver
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False

console = Console()

FINGERPRINTS: list[dict] = [
    {"service": "GitHub Pages",    "cnames": ["github.io", "githubusercontent.com"],
     "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"],
     "nxdomain": False},
    {"service": "Heroku",          "cnames": ["herokuapp.com", "herokudns.com", "herokussl.com"],
     "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
     "nxdomain": False},
    {"service": "AWS S3",          "cnames": ["s3.amazonaws.com", "s3-website", ".s3.", "amazonaws.com"],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
     "nxdomain": False},
    {"service": "AWS CloudFront",  "cnames": ["cloudfront.net"],
     "fingerprints": ["The request could not be satisfied", "ERROR: The request could not be satisfied"],
     "nxdomain": False},
    {"service": "AWS Elastic Beanstalk", "cnames": ["elasticbeanstalk.com"],
     "fingerprints": ["NXDOMAIN"],
     "nxdomain": True},
    {"service": "Azure",           "cnames": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                                              "trafficmanager.net", "blob.core.windows.net", "azure-api.net",
                                              "azurehdinsight.net", "azureedge.net", "azurecontainer.io",
                                              "azuredatalakestore.net", "servicebus.windows.net"],
     "fingerprints": ["404 Web Site not found", "The resource you are looking for has been removed"],
     "nxdomain": True},
    {"service": "Shopify",         "cnames": ["myshopify.com"],
     "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left!"],
     "nxdomain": False},
    {"service": "Fastly",          "cnames": ["fastly.net", "fastlylb.net"],
     "fingerprints": ["Fastly error: unknown domain", "Please check that this domain has been added to a service"],
     "nxdomain": False},
    {"service": "Netlify",         "cnames": ["netlify.app", "netlify.com", "netlifyglobalcdn.com"],
     "fingerprints": ["Not Found - Request ID", "Not found - Request ID"],
     "nxdomain": False},
    {"service": "Vercel",          "cnames": ["vercel.app", "vercel-dns.com", "now.sh", "zeit.co"],
     "fingerprints": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND", "404: NOT_FOUND"],
     "nxdomain": False},
    {"service": "Surge.sh",        "cnames": ["surge.sh"],
     "fingerprints": ["project not found"],
     "nxdomain": False},
    {"service": "Bitbucket",       "cnames": ["bitbucket.io"],
     "fingerprints": ["Repository not found", "The page you have requested does not exist"],
     "nxdomain": False},
    {"service": "Ghost",           "cnames": ["ghost.io"],
     "fingerprints": ["The thing you were looking for is no longer here", "Domain error"],
     "nxdomain": False},
    {"service": "Help Scout",      "cnames": ["helpscoutdocs.com"],
     "fingerprints": ["No settings were found for this company"],
     "nxdomain": False},
    {"service": "Cargo",           "cnames": ["cargocollective.com"],
     "fingerprints": ["404 Not Found", "If you're moving your domain away from Cargo"],
     "nxdomain": False},
    {"service": "Tumblr",          "cnames": ["domains.tumblr.com"],
     "fingerprints": ["Whatever you were looking for doesn't currently exist at this address", "There's nothing here"],
     "nxdomain": False},
    {"service": "WordPress",       "cnames": ["wordpress.com"],
     "fingerprints": ["Do you want to register"],
     "nxdomain": False},
    {"service": "Teamwork",        "cnames": ["teamwork.com"],
     "fingerprints": ["Oops - We didn't find your site"],
     "nxdomain": False},
    {"service": "Unbounce",        "cnames": ["unbouncepages.com"],
     "fingerprints": ["The requested URL was not found on this server", "Sorry, the page you were looking for doesn't exist"],
     "nxdomain": False},
    {"service": "Helpjuice",       "cnames": ["helpjuice.com"],
     "fingerprints": ["We could not find what you're looking for"],
     "nxdomain": False},
    {"service": "Pingdom",         "cnames": ["stats.pingdom.com"],
     "fingerprints": ["pingdom"],
     "nxdomain": False},
    {"service": "Tilda",           "cnames": ["tilda.ws"],
     "fingerprints": ["Please renew your subscription", "Domain has been assigned"],
     "nxdomain": False},
    {"service": "WP Engine",       "cnames": ["wpengine.com"],
     "fingerprints": ["The site you were looking for couldn't be found"],
     "nxdomain": False},
    {"service": "Pantheon",        "cnames": ["pantheonsite.io"],
     "fingerprints": ["The gods are wise", "404 error unknown site"],
     "nxdomain": False},
    {"service": "StatusPage",      "cnames": ["statuspage.io"],
     "fingerprints": ["You are being redirected", "This page is parked"],
     "nxdomain": False},
    {"service": "Zendesk",         "cnames": ["zendesk.com"],
     "fingerprints": ["Help Center Closed", "this help center no longer exists"],
     "nxdomain": False},
    {"service": "Readme.io",       "cnames": ["readme.io"],
     "fingerprints": ["Project doesnt exist... yet!"],
     "nxdomain": False},
    {"service": "Strikingly",      "cnames": ["s.strikinglydns.com", "strikingly.com"],
     "fingerprints": ["page not found", "But if you're looking to build your own website"],
     "nxdomain": False},
    {"service": "UserVoice",       "cnames": ["uservoice.com"],
     "fingerprints": ["This UserVoice subdomain is currently available"],
     "nxdomain": False},
    {"service": "Webflow",         "cnames": ["proxy-ssl.webflow.com", "webflow.io"],
     "fingerprints": ["The page you are looking for doesn't exist or has been moved"],
     "nxdomain": False},
    {"service": "JetBrains",       "cnames": ["myjetbrains.com"],
     "fingerprints": ["is not a registered InCloud YouTrack"],
     "nxdomain": False},
    {"service": "Smartling",       "cnames": ["smartling.com"],
     "fingerprints": ["Domain is not configured"],
     "nxdomain": False},
    {"service": "Acquia",          "cnames": ["acquia-sites.com"],
     "fingerprints": ["The site you are looking for could not be found"],
     "nxdomain": False},
    {"service": "Campaign Monitor","cnames": ["createsend.com"],
     "fingerprints": ["Trying to access your account?", "double-check the URL"],
     "nxdomain": False},
    {"service": "Canny",           "cnames": ["canny.io"],
     "fingerprints": ["Company Not Found", "There is no such company"],
     "nxdomain": False},
    {"service": "AfterShip",       "cnames": ["aftership.com"],
     "fingerprints": ["Oops.</h2><p class=\"text-muted\">The page you're looking for doesn't exist"],
     "nxdomain": False},
    {"service": "Big Cartel",      "cnames": ["bigcartel.com"],
     "fingerprints": ["<h1>Oops! We couldn&#8217;t find that page.</h1>"],
     "nxdomain": False},
    {"service": "Freshdesk",       "cnames": ["freshdesk.com"],
     "fingerprints": ["May be this is still fresh!"],
     "nxdomain": False},
    {"service": "Intercom",        "cnames": ["custom.intercom.help"],
     "fingerprints": ["This page is reserved for artistic dogs", "Uh oh. That page doesn't exist"],
     "nxdomain": False},
    {"service": "Launchrock",      "cnames": ["launchrock.com"],
     "fingerprints": ["It looks like you may have taken a wrong turn somewhere"],
     "nxdomain": False},
    {"service": "Short.io",        "cnames": ["cname.short.io", "short.io"],
     "fingerprints": ["Link does not exist", "This domain is not configured on Short.io yet"],
     "nxdomain": False},
    {"service": "Thinkific",       "cnames": ["thinkific.com"],
     "fingerprints": ["You don't have a Thinkific site at this address"],
     "nxdomain": False},
    {"service": "Wix",             "cnames": ["wixdns.net"],
     "fingerprints": ["Error ConnectYourDomain occurred"],
     "nxdomain": False},
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class TakeoverFinding:
    subdomain:    str
    cname:        Optional[str]
    service:      str
    status:       int
    confirmed:    bool
    evidence:     str           = ""
    severity:     str           = "high"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class TakeoverReport:
    target:       str
    started_at:   str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:  Optional[str]            = None
    checked:      int                      = 0
    findings:     list[TakeoverFinding]    = field(default_factory=list)
    errors:       list[str]                = field(default_factory=list)

    @property
    def critical(self) -> list[TakeoverFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> list[TakeoverFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _normalize(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or target).strip().lower()


async def _resolve_cname(host: str) -> tuple[Optional[str], bool]:
    if not _HAS_DNS:
        return None, False
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 8
        answer = await resolver.resolve(host, "CNAME")
        for rdata in answer:
            return str(rdata.target).rstrip(".").lower(), False
    except dns.resolver.NXDOMAIN:
        return None, True
    except Exception:
        return None, False
    return None, False


def _match_service(cname: Optional[str], nxdomain: bool, body: str) -> Optional[dict]:
    body_lower = body.lower()
    for fp in FINGERPRINTS:
        cname_hit = cname is not None and any(c.lower() in cname for c in fp["cnames"])
        if not cname_hit:
            continue
        if fp["nxdomain"] and nxdomain:
            return {"service": fp["service"], "evidence": "Dangling CNAME (NXDOMAIN)", "confirmed": True}
        for needle in fp["fingerprints"]:
            if needle.lower() in body_lower:
                return {"service": fp["service"], "evidence": needle[:120], "confirmed": True}
        return {"service": fp["service"], "evidence": "CNAME points to provider, no claim fingerprint", "confirmed": False}
    return None


async def _check_one(
    client: httpx.AsyncClient,
    host:   str,
    sem:    asyncio.Semaphore,
) -> Optional[TakeoverFinding]:

    async with sem:
        cname, nxdomain = await _resolve_cname(host)

        body = ""
        status = 0
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{host}", timeout=10)
                body   = r.text
                status = r.status_code
                break
            except Exception:
                continue

        match = _match_service(cname, nxdomain, body)
        if not match:
            return None

        severity = "critical" if match["confirmed"] else "high"
        finding = TakeoverFinding(
            subdomain=host,
            cname=cname,
            service=match["service"],
            status=status,
            confirmed=match["confirmed"],
            evidence=match["evidence"],
            severity=severity,
        )
        _print_finding(finding)
        return finding


def _print_finding(f: TakeoverFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    state = "CONFIRMED" if f.confirmed else "POTENTIAL"
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.subdomain}[/bold white] → "
        f"[yellow]{f.service}[/yellow] "
        f"[dim]({state})[/dim] "
        f"[dim]cname: {f.cname or '-'}[/dim]"
    )


def _display(report: TakeoverReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]checked:[/dim] {report.checked}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]confirmed:[/dim] [red]{len(report.critical)}[/red]",
        title="[bold red]Subdomain Takeover — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No takeover candidates found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Subdomain", style="bold white", min_width=30)
    table.add_column("Service",   style="cyan", width=18)
    table.add_column("CNAME",     style="dim", min_width=25)
    table.add_column("State",     width=11)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.subdomain,
            f.service,
            f.cname or "-",
            "confirmed" if f.confirmed else "potential",
        )

    console.print(table)
    console.print()


async def _takeover_async(
    hosts:       list[str],
    concurrency: int,
    proxy:       Optional[str],
) -> TakeoverReport:

    target  = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"
    report  = TakeoverReport(target=target)
    sem     = asyncio.Semaphore(concurrency)

    if not _HAS_DNS:
        report.errors.append("dnspython not available — CNAME resolution disabled")
        console.print("[yellow]    [!] dnspython missing, body fingerprints only[/yellow]")

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=35, style="red", complete_style="green"),
            TextColumn("[green]{task.completed}[/green]/[white]{task.total}[/white]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Checking takeover...", total=len(hosts))

            tasks = [_check_one(client, host, sem) for host in hosts]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                report.checked += 1
                if result:
                    report.findings.append(result)
                progress.advance(task_id, 1)

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_subdomain_takeover(
    target:      str,
    subdomains:  Optional[list[str]] = None,
    concurrency: int                 = 30,
    proxy:       Optional[str]       = None,
    save_json:   Optional[str]       = None,
) -> TakeoverReport:

    hosts = [_normalize(s) for s in subdomains] if subdomains else [_normalize(target)]
    hosts = sorted(set(h for h in hosts if h))

    console.print(f"\n[bold red][*][/bold red] Subdomain Takeover → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Hosts: {len(hosts)}  Fingerprints: {len(FINGERPRINTS)}[/dim]")

    report = asyncio.run(_takeover_async(
        hosts=hosts,
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
