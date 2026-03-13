import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

VALID_STATUSES = {
    200, 201, 202, 204,
    301, 302, 307, 308,
    401, 403, 405, 407,
    500, 502, 503,
}

IGNORE_STATUSES = {404, 410, 444, 400}

CRITICAL_PATHS = {
    "admin", "administrator", "backoffice", "console", "dashboard",
    "debug", "internal", "private", "hidden",
    "actuator", "actuator/health", "actuator/env", "actuator/heapdump",
    "actuator/shutdown", "actuator/beans", "actuator/mappings",
    "graphql", "graphiql", "playground",
    "swagger", "swagger-ui", "swagger-ui.html", "api-docs",
    "openapi.json", "openapi.yaml",
    ".env", ".git", ".git/config", ".git/HEAD",
    "config", "settings", "secrets", "credentials",
    "server-status", "server-info",
    "phpinfo.php", "info.php", "adminer", "phpmyadmin",
    "backup", "dump", "export", "restore",
    "metrics", "prometheus", "health", "healthz",
}

INTERESTING_BODY = [
    (r"swagger|openapi|api.?doc",                "API docs"),
    (r"graphql|__schema|__typename",             "GraphQL"),
    (r"traceback|stack.?trace|exception|error",  "Error/stacktrace"),
    (r"index of /|directory listing",            "Directory listing"),
    (r"root:.*:/bin/|/etc/passwd",               "/etc/passwd"),
    (r"aws_access_key|AKIA[0-9A-Z]{16}",        "AWS credentials"),
    (r"password|passwd|secret|token|api.?key",   "Sensitive data"),
    (r"phpinfo\(\)|php version",                 "PHPInfo"),
    (r"welcome to nginx|apache2 default",        "Default page"),
    (r"\"version\"\s*:",                         "Version info"),
    (r"\"debug\"\s*:\s*true",                    "Debug mode on"),
    (r"internal server error|500",               "500 error"),
]

@dataclass
class EndpointResult:
    url:           str
    path:          str
    status:        int
    method:        str             = "GET"
    redirect_url:  Optional[str]  = None
    title:         Optional[str]  = None
    content_type:  Optional[str]  = None
    content_len:   Optional[int]  = None
    server:        Optional[str]  = None
    response_time: Optional[float]= None
    interesting:   bool           = False
    critical:      bool           = False
    notes:         list[str]      = field(default_factory=list)
    timestamp:     str            = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class DiscoveryReport:
    target:        str
    started_at:    str            = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:   Optional[str] = None
    total_tested:  int            = 0
    found:         list[EndpointResult] = field(default_factory=list)
    errors:        list[str]      = field(default_factory=list)

    @property
    def critical(self) -> list[EndpointResult]:
        return [r for r in self.found if r.critical]

    @property
    def interesting(self) -> list[EndpointResult]:
        return [r for r in self.found if r.interesting]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["found"]    = [e.to_dict() for e in self.found]
        d["critical"] = [e.to_dict() for e in self.critical]
        return d

async def _calibrate(client: httpx.AsyncClient, target: str) -> set[str]:
    canaries = [
        "prothos-canary-x7q9z",
        "prothos-canary-a3f8k",
    ]
    baselines = set()
    for canary in canaries:
        try:
            url = urljoin(target.rstrip("/") + "/", canary)
            r   = await client.get(url, timeout=8)
            fingerprint = f"{r.status_code}:{r.text[:200]}"
            baselines.add(fingerprint)
        except Exception:
            pass
    return baselines

def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:80] if m else None


def _analyze(
    path:          str,
    status:        int,
    headers:       dict,
    body:          str,
    response_time: float,
    baselines:     set[str],
) -> tuple[bool, bool, list[str]]:

    notes:       list[str] = []
    interesting  = False
    critical     = False

    fingerprint = f"{status}:{body[:200]}"
    if fingerprint in baselines:
        return False, False, ["soft-404 (baseline match)"]

    clean = path.strip("/").lower().split("?")[0]
    if any(clean == cp or clean.startswith(cp + "/") for cp in CRITICAL_PATHS):
        notes.append("⚠ Critical path")
        critical    = True
        interesting = True

    if status in {401, 403}:
        notes.append("🔒 Auth required")
        interesting = True
    elif status in {500, 502, 503}:
        notes.append(" Server error")
        interesting = True
    elif status in {301, 302, 307, 308}:
        loc = headers.get("location", "")
        notes.append(f"↪ → {loc[:60]}" if loc else "↪ Redirect")

    if response_time > 5.0:
        notes.append(f" Slow ({response_time:.1f}s)")

    body_sample = body[:8000].lower()
    for pattern, label in INTERESTING_BODY:
        if re.search(pattern, body_sample, re.IGNORECASE):
            notes.append(f" {label}")
            interesting = True

    if headers.get("x-powered-by"):
        notes.append(f"Powered-By: {headers['x-powered-by']}")
        interesting = True
    if headers.get("server"):
        notes.append(f"Server: {headers['server']}")
    if "x-debug" in headers or "x-debug-token" in headers:
        notes.append(" Debug headers")
        interesting = True

    return interesting, critical, notes

async def _probe(
    client:    httpx.AsyncClient,
    target:    str,
    path:      str,
    sem:       asyncio.Semaphore,
    baselines: set[str],
) -> Optional[EndpointResult]:

    url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))

    async with sem:
        import time
        try:
            t0 = time.perf_counter()
            r  = await client.get(url, timeout=10)
            elapsed = round(time.perf_counter() - t0, 3)

            if r.status_code in IGNORE_STATUSES:
                return None

            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            body          = r.text
            title         = _extract_title(body) if "html" in headers_lower.get("content-type", "") else None
            redirect      = headers_lower.get("location")

            interesting, critical, notes = _analyze(
                path, r.status_code, headers_lower, body, elapsed, baselines
            )

            return EndpointResult(
                url=str(r.url),
                path=path,
                status=r.status_code,
                redirect_url=redirect,
                title=title,
                content_type=headers_lower.get("content-type", "")[:60],
                content_len=int(headers_lower.get("content-length", 0) or len(r.content)),
                server=headers_lower.get("server"),
                response_time=elapsed,
                interesting=interesting,
                critical=critical,
                notes=notes,
            )

        except httpx.TimeoutException:
            return None
        except Exception:
            return None


async def _discover_async(
    target:      str,
    wordlist:    list[str],
    concurrency: int,
    proxy:       Optional[str],
) -> DiscoveryReport:

    report  = DiscoveryReport(target=target)
    sem     = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
        proxy=proxy,
    ) as client:

        console.print("[dim]    Calibrating baselines...[/dim]")
        baselines = await _calibrate(client, target)
        console.print(f"[dim]    Baseline fingerprints: {len(baselines)}[/dim]\n")

        tasks         = [_probe(client, target, path, sem, baselines) for path in wordlist]
        report.total_tested = len(tasks)

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=35, style="red", complete_style="green"),
            TextColumn("[green]{task.completed}[/green]/[white]{task.total}[/white]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(
                f"Discovering [bold red]{urlparse(target).netloc}[/bold red]",
                total=len(tasks),
            )

            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    report.found.append(result)
                    _print_found(result)
                progress.advance(task_id, 1)

    report.found.sort(key=lambda x: (x.status, x.path))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report

def _status_color(status: int) -> str:
    if status < 300:  return "green"
    if status < 400:  return "yellow"
    if status < 500:  return "cyan"
    return "red"


def _print_found(r: EndpointResult):
    color    = _status_color(r.status)
    flag     = " [bold red]★[/bold red]" if r.critical else (" [yellow]•[/yellow]" if r.interesting else "")
    title    = f" [dim italic]{r.title}[/dim italic]" if r.title else ""
    redirect = f" [dim]→ {r.redirect_url}[/dim]" if r.redirect_url else ""
    t        = f" [dim]{r.response_time}s[/dim]" if r.response_time else ""
    console.print(
        f"  [{color}]{r.status}[/{color}] "
        f"[bold white]{r.path}[/bold white]"
        f"{title}{redirect}{t}{flag}"
    )


def _display_summary(report: DiscoveryReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]tested:[/dim] {report.total_tested}  "
        f"[dim]found:[/dim] [green]{len(report.found)}[/green]  "
        f"[dim]interesting:[/dim] [yellow]{len(report.interesting)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]",
        title="[bold red]Endpoint Discovery — Summary[/bold red]",
        border_style="red",
    ))

    if not report.found:
        console.print("[dim]  No endpoints found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Status", style="bold",        width=7)
    table.add_column("Path",   style="bold white",  min_width=30)
    table.add_column("Title",  style="dim italic",  min_width=20)
    table.add_column("Size",   style="dim",          width=8)
    table.add_column("Time",   style="dim",          width=7)
    table.add_column("Notes",  style="yellow",       min_width=25)

    for r in report.found:
        color  = _status_color(r.status)
        status = f"[{color}]{r.status}[/{color}]"
        size   = f"{r.content_len}b" if r.content_len else "-"
        t      = f"{r.response_time}s" if r.response_time else "-"
        notes  = " | ".join(r.notes[:2]) if r.notes else "-"
        table.add_row(status, r.path, r.title or "-", size, t, notes)

    console.print(table)

    if report.critical:
        console.print(f"\n[bold red][!] CRITICAL FINDINGS: {len(report.critical)}[/bold red]")
        for r in report.critical:
            c = _status_color(r.status)
            console.print(
                f"    [red]→[/red] [{c}]{r.status}[/{c}] "
                f"[bold]{r.path}[/bold]  {' | '.join(r.notes)}"
            )

    console.print()

def run_endpoint_discovery(
    target:        str,
    wordlist_path: str         = "wordlist/endpoints.txt",
    concurrency:   int         = 50,
    proxy:         Optional[str] = None,
    save_json:     Optional[str] = None,
) -> DiscoveryReport:
    
    from utils.wordlist_loader import load_wordlist

    console.print(f"\n[bold red][*][/bold red] Endpoint discovery → [bold white]{target}[/bold white]")

    try:
        wordlist = load_wordlist(wordlist_path)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red][!] {e}[/red]")
        return DiscoveryReport(target=target)

    console.print(f"[dim]    Wordlist: {wordlist_path} ({len(wordlist)} paths)  "
                  f"Concurrency: {concurrency}[/dim]")

    report = asyncio.run(_discover_async(
        target=target,
        wordlist=wordlist,
        concurrency=concurrency,
        proxy=proxy,
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