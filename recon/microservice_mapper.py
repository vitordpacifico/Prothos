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

@dataclass
class ServiceResult:
    url:          str
    path:         str
    status:       int
    method:       str              = "GET"
    redirect_url: Optional[str]   = None
    title:        Optional[str]   = None
    content_type: Optional[str]   = None
    content_len:  Optional[int]   = None
    server:       Optional[str]   = None
    response_time:Optional[float] = None
    interesting:  bool            = False
    notes:        list[str]       = field(default_factory=list)
    timestamp:    str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return self.__dict__.copy()
@dataclass
class MicroserviceReport:
    target:       str
    started_at:   str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:  Optional[str]   = None
    total_tested: int             = 0
    found:        list[ServiceResult] = field(default_factory=list)
    errors:       list[str]       = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["found"] = [s.to_dict() for s in self.found]
        return d

VALID_STATUSES = {
    200, 201, 202, 204,
    301, 302, 307, 308,
    400, 401, 403, 405, 407,
    500, 502, 503,
}

IGNORE_STATUSES = {404, 410, 444}

CRITICAL_PATHS = {
    "admin", "admin/", "internal", "debug", "console",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "actuator/heapdump", "actuator/shutdown", "actuator/mappings",
    "graphql", "graphiql", "playground",
    ".env", ".git", ".git/config", "config", "secrets",
    "swagger", "swagger-ui", "swagger-ui.html", "api-docs",
    "openapi.json", "openapi.yaml",
    "phpmyadmin", "adminer", "phpinfo.php",
    "server-status", "server-info",
    "metrics", "prometheus", "health",
    "backup", "dump", "export",
}

INTERESTING_BODY_PATTERNS = [
    (r"swagger|openapi|api.?doc",       "API docs exposed"),
    (r"graphql|__schema|__typename",    "GraphQL endpoint"),
    (r"error|exception|traceback|stack.?trace", "Error/stack trace leaked"),
    (r"admin|dashboard|panel|console",  "Admin interface"),
    (r"login|sign.?in|authenticate",    "Auth endpoint"),
    (r"password|passwd|secret|token|api.?key", "Sensitive data in response"),
    (r"internal server error|500",      "500 error"),
    (r"index of /|directory listing",   "Directory listing"),
    (r"welcome to nginx|apache2 default","Default server page"),
    (r"phpinfo\(\)|php version",        "PHPInfo exposed"),
    (r"root:.*:/bin/",                  "Unix /etc/passwd leaked"),
    (r"aws_access_key|aws_secret",      "AWS credentials leaked"),
]

def _analyze_response(
    path:     str,
    status:   int,
    headers:  dict,
    body:     str,
    response_time: float,
) -> tuple[bool, list[str]]:
    """
    Analisa resposta e retorna (interesting: bool, notes: list[str]).
    """
    notes:    list[str] = []
    interesting = False

    clean_path = path.strip("/").lower()
    if any(clean_path == cp or clean_path.startswith(cp) for cp in CRITICAL_PATHS):
        notes.append("⚠ Critical path")
        interesting = True

    if status in {401, 403}:
        notes.append(" Auth required — service exists")
        interesting = True
    elif status in {500, 502, 503}:
        notes.append(" Server error — may be unstable")
        interesting = True
    elif status in {301, 302, 307, 308}:
        notes.append("↪ Redirect")

    if response_time > 5.0:
        notes.append(f" Slow response ({response_time:.1f}s)")

    body_lower = body[:5000].lower()
    for pattern, label in INTERESTING_BODY_PATTERNS:
        if re.search(pattern, body_lower, re.IGNORECASE):
            notes.append(f" {label}")
            interesting = True

    server = headers.get("server", "")
    if server:
        notes.append(f"Server: {server}")

    powered = headers.get("x-powered-by", "")
    if powered:
        notes.append(f"X-Powered-By: {powered}")
        interesting = True

    if "x-debug" in headers or "x-debug-token" in headers:
        notes.append("🐛 Debug headers exposed")
        interesting = True

    return interesting, notes


def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:80] if m else None

async def _probe_service(
    client:  httpx.AsyncClient,
    target:  str,
    path:    str,
    methods: list[str],
    sem:     asyncio.Semaphore,
) -> list[ServiceResult]:
    """Testa um path com um ou mais métodos HTTP."""
    results = []
    url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))

    async with sem:
        for method in methods:
            try:
                import time
                t0 = time.perf_counter()
                r  = await client.request(method, url, timeout=10)
                elapsed = time.perf_counter() - t0

                if r.status_code in IGNORE_STATUSES:
                    continue

                headers_lower = {k.lower(): v for k, v in r.headers.items()}
                body          = r.text
                title         = _extract_title(body) if "html" in headers_lower.get("content-type", "") else None
                redirect      = str(r.headers.get("location", "")) or None

                interesting, notes = _analyze_response(
                    path, r.status_code, headers_lower, body, elapsed
                )

                result = ServiceResult(
                    url=str(r.url),
                    path=path,
                    status=r.status_code,
                    method=method,
                    redirect_url=redirect,
                    title=title,
                    content_type=headers_lower.get("content-type", "")[:60],
                    content_len=int(headers_lower.get("content-length", 0) or len(r.content)),
                    server=headers_lower.get("server"),
                    response_time=round(elapsed, 3),
                    interesting=interesting,
                    notes=notes,
                )
                results.append(result)
                _print_found(result)

            except httpx.TimeoutException:
                pass
            except Exception:
                pass

    return results


async def _map_async(
    target:      str,
    wordlist:    list[str],
    concurrency: int = 50,
    methods:     list[str] = None,
    proxy:       Optional[str] = None,
) -> MicroserviceReport:

    report  = MicroserviceReport(target=target)
    methods = methods or ["GET"]
    sem     = asyncio.Semaphore(concurrency)

    proxies = {"http://": proxy, "https://": proxy} if proxy else None

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
        proxies=proxies,
    ) as client:

        tasks = [
            _probe_service(client, target, path, methods, sem)
            for path in wordlist
        ]

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
                f"Mapping [bold red]{urlparse(target).netloc}[/bold red]",
                total=len(tasks),
            )

            for coro in asyncio.as_completed(tasks):
                results = await coro
                for r in results:
                    report.found.append(r)
                progress.advance(task_id, 1)

    report.found.sort(key=lambda x: (x.status, x.path))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report

def _status_color(status: int) -> str:
    if status < 300:   return "green"
    if status < 400:   return "yellow"
    if status < 500:   return "cyan"
    return "red"


def _print_found(r: ServiceResult):
    color    = _status_color(r.status)
    flag     = " [bold red]★[/bold red]" if r.interesting else ""
    title    = f" [dim italic]{r.title}[/dim italic]" if r.title else ""
    redirect = f" [dim]→ {r.redirect_url}[/dim]" if r.redirect_url else ""
    time_str = f" [dim]{r.response_time}s[/dim]" if r.response_time else ""
    console.print(
        f"  [{color}]{r.status}[/{color}] "
        f"[bold white]{r.path}[/bold white]"
        f"{title}{redirect}{time_str}{flag}"
    )


def _display_summary(report: MicroserviceReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]tested:[/dim] {report.total_tested}  "
        f"[dim]found:[/dim] [green]{len(report.found)}[/green]  "
        f"[dim]interesting:[/dim] [red]{sum(1 for r in report.found if r.interesting)}[/red]",
        title="[bold red]Microservice Mapper — Summary[/bold red]",
        border_style="red",
    ))

    if not report.found:
        console.print("[dim]  No services found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Status", style="bold",       width=7)
    table.add_column("Method", style="dim",        width=7)
    table.add_column("Path",   style="bold white", min_width=30)
    table.add_column("Title",  style="dim italic", min_width=20)
    table.add_column("Size",   style="dim",        width=8)
    table.add_column("Time",   style="dim",        width=7)
    table.add_column("Notes",  style="yellow",     min_width=25)

    for r in report.found:
        color  = _status_color(r.status)
        status = f"[{color}]{r.status}[/{color}]"
        size   = f"{r.content_len}b" if r.content_len else "-"
        t      = f"{r.response_time}s" if r.response_time else "-"
        notes  = " | ".join(r.notes[:2]) if r.notes else "-"
        table.add_row(status, r.method, r.path, r.title or "-", size, t, notes)

    console.print(table)

    critical = [r for r in report.found if r.interesting]
    if critical:
        console.print(f"\n[bold red][!] INTERESTING FINDINGS: {len(critical)}[/bold red]")
        for r in critical:
            console.print(f"    [red]→[/red] [{_status_color(r.status)}]{r.status}[/{_status_color(r.status)}] "
                         f"[bold]{r.path}[/bold]  {' | '.join(r.notes)}")
    console.print()

def map_services(
    target:       str,
    wordlist_path: str = "wordlists/microservices.txt",
    concurrency:  int  = 50,
    methods:      list[str] = None,
    proxy:        Optional[str] = None,
    save_json:    Optional[str] = None,
) -> MicroserviceReport:
    
    from utils.wordlist_loader import load_wordlist

    console.print(f"\n[bold red][*][/bold red] Microservice mapping → [bold white]{target}[/bold white]")

    try:
        wordlist = load_wordlist(wordlist_path)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red][!] {e}[/red]")
        return MicroserviceReport(target=target)

    console.print(f"[dim]    Wordlist: {wordlist_path} ({len(wordlist)} paths)  "
                  f"Concurrency: {concurrency}  Methods: {methods or ['GET']}[/dim]\n")

    report = asyncio.run(_map_async(
        target=target,
        wordlist=wordlist,
        concurrency=concurrency,
        methods=methods or ["GET"],
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