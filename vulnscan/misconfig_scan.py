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
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

SECURITY_HEADERS: list[tuple[str, str, str]] = [
    ("content-security-policy",      "Missing Content-Security-Policy", "medium"),
    ("strict-transport-security",    "Missing HSTS", "medium"),
    ("x-frame-options",              "Missing X-Frame-Options (clickjacking)", "medium"),
    ("x-content-type-options",       "Missing X-Content-Type-Options (MIME sniffing)", "low"),
    ("referrer-policy",              "Missing Referrer-Policy", "low"),
    ("permissions-policy",           "Missing Permissions-Policy", "low"),
]

EXPOSED_PATHS: list[tuple[str, str, str]] = [
    ("/.git/config",            "Exposed .git repository", "high"),
    ("/.git/HEAD",              "Exposed .git repository", "high"),
    ("/.env",                   "Exposed .env file", "critical"),
    ("/.env.local",             "Exposed .env.local", "critical"),
    ("/config.json",            "Exposed config.json", "medium"),
    ("/wp-config.php.bak",      "Exposed WP config backup", "critical"),
    ("/.svn/entries",           "Exposed .svn", "high"),
    ("/.DS_Store",              "Exposed .DS_Store", "low"),
    ("/server-status",          "Apache server-status exposed", "medium"),
    ("/server-info",            "Apache server-info exposed", "medium"),
    ("/actuator",               "Spring Actuator exposed", "high"),
    ("/actuator/env",           "Spring Actuator env exposed", "critical"),
    ("/actuator/health",        "Spring Actuator health exposed", "low"),
    ("/phpinfo.php",            "phpinfo() exposed", "high"),
    ("/info.php",               "phpinfo() exposed", "high"),
    ("/.well-known/security.txt","security.txt present", "info"),
    ("/swagger-ui.html",        "Swagger UI exposed", "low"),
    ("/api-docs",               "API docs exposed", "low"),
    ("/.dockerenv",             "Docker env marker", "info"),
    ("/backup.zip",             "Exposed backup archive", "high"),
    ("/.aws/credentials",       "Exposed AWS credentials", "critical"),
    ("/debug",                  "Debug endpoint", "medium"),
    ("/trace",                  "Trace endpoint", "medium"),
]

LISTING_RE = re.compile(r"<title>Index of /|Directory listing for|\[To Parent Directory\]", re.IGNORECASE)
VERBOSE_ERR_RE = re.compile(r"(?:stack trace|traceback \(most recent|Whitelabel Error Page|"
                            r"Warning: .* on line \d+|Fatal error:|Exception in thread)", re.IGNORECASE)

SEVERITY_COLOR = {
    "critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "cyan",
}


@dataclass
class MisconfigFinding:
    kind:       str
    location:   str
    detail:     str
    status:     int          = 0
    severity:   str          = "low"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class MisconfigReport:
    target:      str
    started_at:  str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None
    findings:    list[MisconfigFinding]   = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    @property
    def critical(self) -> list[MisconfigFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> list[MisconfigFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _add(report, kind, location, detail, severity, status=0):
    f = MisconfigFinding(kind=kind, location=location, detail=detail, severity=severity, status=status)
    report.findings.append(f)
    _print_finding(f)


async def _check_headers(client, target, report):
    try:
        r = await client.get(target, timeout=12)
    except Exception as e:
        report.errors.append(f"header check: {str(e)[:100]}")
        return
    headers = {k.lower(): v for k, v in r.headers.items()}

    for hdr, label, sev in SECURITY_HEADERS:
        if hdr not in headers:
            _add(report, "Missing security header", target, label, sev, r.status_code)

    server = headers.get("server", "")
    if server and re.search(r"\d", server):
        _add(report, "Version disclosure", target, f"Server header reveals version: {server}", "low", r.status_code)
    powered = headers.get("x-powered-by", "")
    if powered:
        _add(report, "Tech disclosure", target, f"X-Powered-By: {powered}", "low", r.status_code)

    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        _add(report, "Permissive CORS", target, "Access-Control-Allow-Origin: *", "medium", r.status_code)

    if VERBOSE_ERR_RE.search(r.text):
        _add(report, "Verbose error", target, "Stack trace / verbose error in response", "medium", r.status_code)


async def _check_paths(client, root, sem, report):
    async def _one(path, label, sev):
        url = urljoin(root, path)
        async with sem:
            try:
                r = await client.get(url, timeout=10)
            except Exception:
                return
            if r.status_code in (200, 206) and len(r.text) > 0:
                low = r.text[:200].lower()
                if "<html" in low and ("not found" in low or "404" in low):
                    return
                _add(report, "Exposed resource", url, label, sev, r.status_code)
                if LISTING_RE.search(r.text):
                    _add(report, "Directory listing", url, "Directory listing enabled", "medium", r.status_code)
    await asyncio.gather(*[_one(p, label, sev) for p, label, sev in EXPOSED_PATHS])


async def _check_methods(client, target, report):
    try:
        r = await client.request("OPTIONS", target, timeout=10)
        allow = r.headers.get("allow", "")
        dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if m in allow.upper()]
        if dangerous:
            _add(report, "Dangerous methods", target, f"Allowed: {', '.join(dangerous)}", "medium", r.status_code)
    except Exception:
        pass


def _print_finding(f: MisconfigFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.kind}[/bold white] → [yellow]{f.detail}[/yellow] "
        f"[dim]{f.location}[/dim]"
    )


def _display(report: MisconfigReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Misconfig Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No misconfigurations found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Kind",     style="cyan", width=24)
    table.add_column("Detail",   style="yellow", min_width=30)

    for f in sorted(report.findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5)):
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.kind, f.detail[:50])

    console.print(table)
    console.print()


async def _misconfig_async(target, concurrency, proxy) -> MisconfigReport:
    report = MisconfigReport(target=target)
    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=35, style="red", complete_style="green"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as progress:
            progress.add_task("Scanning misconfigs...", total=None)
            await _check_headers(client, target, report)
            await _check_methods(client, target, report)
            await _check_paths(client, root, sem, report)

    report.findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_misconfig_scan(
    target:      str,
    concurrency: int            = 15,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> MisconfigReport:

    console.print(f"\n[bold red][*][/bold red] Misconfig Scan → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Headers: {len(SECURITY_HEADERS)}  Paths: {len(EXPOSED_PATHS)}[/dim]")

    report = asyncio.run(_misconfig_async(target, concurrency, proxy))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
