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

console = Console()

@dataclass
class APIVersionResult:
    url:           str
    version:       str
    status:        int
    content_len:   int                = 0
    content_type:  Optional[str]      = None
    title:         Optional[str]      = None
    response_time: float              = 0.0
    is_json:       bool               = False
    interesting:   bool               = False
    deprecated:    bool               = False
    notes:         list[str]          = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class APIVersionReport:
    target:        str
    started_at:    str                        = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:   Optional[str]             = None
    total_tested:  int                        = 0
    found:         list[APIVersionResult]     = field(default_factory=list)
    errors:        list[str]                 = field(default_factory=list)

    @property
    def interesting(self) -> list[APIVersionResult]:
        return [r for r in self.found if r.interesting]

    @property
    def deprecated(self) -> list[APIVersionResult]:
        return [r for r in self.found if r.deprecated]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["found"] = [r.to_dict() for r in self.found]
        return d

VERSION_PATTERNS = [
    "v0", "v1", "v2", "v3", "v4", "v5",
    "v1.0", "v1.1", "v2.0", "v2.1", "v3.0",

    "api/v0", "api/v1", "api/v2", "api/v3", "api/v4",
    "api/v1.0", "api/v2.0",

    "rest/v1", "rest/v2", "rest/v3",

    "api", "rest", "service", "services",
    "graphql", "gql",

    "2020-01", "2021-01", "2022-01", "2023-01", "2024-01",
    "api/2020-01", "api/2021-01", "api/2022-01",
    "api/2023-01", "api/2024-01",

    "api/internal", "api/legacy", "api/beta",
    "api/alpha", "api/dev", "api/stable",
    "api/private", "api/public",

    "api/mobile", "api/ios", "api/android",
    "mobile/v1", "mobile/v2",

    "api/partner", "api/external", "api/third-party",

    "api/v1/docs", "api/v2/docs",
    "api/v1/swagger", "api/v2/swagger",
    "api/v1/openapi", "api/v2/openapi",
    "api/v1/health", "api/v2/health",
    "api/v1/status", "api/v2/status",
]

DEPRECATED_HINTS = [
    "deprecated", "legacy", "old", "v0", "v1",
    "sunset", "end-of-life", "eol", "obsolete",
]

INTERESTING_BODY = [
    (r"swagger|openapi",             "API docs"),
    (r"graphql|__schema",            "GraphQL"),
    (r"\"version\"\s*:",             "Version info"),
    (r"\"endpoints\"\s*:",           "Endpoint list"),
    (r"\"routes\"\s*:",              "Route list"),
    (r"error|exception|traceback",   "Error exposed"),
    (r"\"debug\"\s*:\s*true",        "Debug mode"),
    (r"welcome|hello|api\s+v",       "API welcome"),
]

def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:80] if m else None


def _analyze(
    version:      str,
    status:       int,
    headers:      dict,
    body:         str,
    elapsed:      float,
) -> tuple[bool, bool, list[str]]:

    notes       = []
    interesting = False
    deprecated  = False

    ct = headers.get("content-type", "")

    if status in (200, 201):
        interesting = True
        notes.append("200 OK")
    elif status in (401, 403):
        notes.append("Auth required")
        interesting = True
    elif status == 405:
        notes.append("Method not allowed")
        interesting = True
    elif status == 500:
        notes.append("Server error")
        interesting = True

    if "json" in ct:
        notes.append("JSON response")

    sunset = headers.get("sunset") or headers.get("deprecation")
    if sunset:
        deprecated  = True
        interesting = True
        notes.append(f"Deprecated: {sunset[:40]}")

    if any(h in version.lower() for h in DEPRECATED_HINTS):
        deprecated = True
        notes.append("Possible legacy version")

    body_lower = body[:5000].lower()
    for pattern, label in INTERESTING_BODY:
        if re.search(pattern, body_lower, re.IGNORECASE):
            notes.append(label)
            interesting = True

    if elapsed > 3.0:
        notes.append(f"Slow ({elapsed:.1f}s)")

    if headers.get("x-api-version"):
        notes.append(f"X-API-Version: {headers['x-api-version']}")
    if headers.get("api-version"):
        notes.append(f"API-Version: {headers['api-version']}")

    return interesting, deprecated, notes

VALID_STATUSES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}
IGNORE_STATUSES = {404, 410, 400, 444}


async def _probe(
    client:  httpx.AsyncClient,
    base:    str,
    version: str,
    sem:     asyncio.Semaphore,
) -> Optional[APIVersionResult]:

    url = urljoin(base.rstrip("/") + "/", version.lstrip("/"))

    async with sem:
        import time
        try:
            t0 = time.perf_counter()
            r  = await client.get(url, timeout=10)
            elapsed = round(time.perf_counter() - t0, 3)

            if r.status_code in IGNORE_STATUSES:
                return None

            headers = {k.lower(): v for k, v in r.headers.items()}
            body    = r.text
            ct      = headers.get("content-type", "")
            title   = _extract_title(body) if "html" in ct else None

            interesting, deprecated, notes = _analyze(
                version, r.status_code, headers, body, elapsed
            )

            return APIVersionResult(
                url=str(r.url),
                version=version,
                status=r.status_code,
                content_len=len(r.content),
                content_type=ct[:60],
                title=title,
                response_time=elapsed,
                is_json="json" in ct,
                interesting=interesting,
                deprecated=deprecated,
                notes=notes,
            )

        except httpx.TimeoutException:
            return None
        except Exception:
            return None

def _status_color(status: int) -> str:
    if status < 300:  return "green"
    if status < 400:  return "yellow"
    if status < 500:  return "cyan"
    return "red"


def _display(report: APIVersionReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]tested:[/dim] {report.total_tested}  "
        f"[dim]found:[/dim] [green]{len(report.found)}[/green]  "
        f"[dim]interesting:[/dim] [yellow]{len(report.interesting)}[/yellow]  "
        f"[dim]deprecated:[/dim] [red]{len(report.deprecated)}[/red]",
        title="[bold red]API Version Enum — Summary[/bold red]",
        border_style="red",
    ))

    if not report.found:
        console.print("[dim]    No API versions found.[/dim]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold red",
        border_style="dim",
    )
    table.add_column("Status",   width=8)
    table.add_column("Version",  width=25)
    table.add_column("URL",      min_width=35, style="cyan")
    table.add_column("Type",     width=8,  style="dim")
    table.add_column("Size",     width=8,  style="dim")
    table.add_column("Time",     width=7,  style="dim")
    table.add_column("Notes",    min_width=20, style="yellow")

    for r in sorted(report.found, key=lambda x: (x.status, x.version)):
        color = _status_color(r.status)
        flag  = " [red][D][/red]" if r.deprecated else ""
        table.add_row(
            f"[{color}]{r.status}[/{color}]",
            r.version + flag,
            r.url[:50],
            "JSON" if r.is_json else "HTML" if r.title else "-",
            f"{r.content_len}b",
            f"{r.response_time}s",
            " | ".join(r.notes[:2]) if r.notes else "-",
        )

    console.print(table)

    if report.deprecated:
        console.print(f"\n[yellow][!] Deprecated/legacy versions: {len(report.deprecated)}[/yellow]")
        for r in report.deprecated:
            c = _status_color(r.status)
            console.print(f"    [yellow]→[/yellow] [{c}]{r.status}[/{c}] {r.url}")

    console.print()

async def _api_version_async(
    target:      str,
    patterns:    list[str],
    concurrency: int,
    proxy:       Optional[str],
) -> APIVersionReport:

    report = APIVersionReport(target=target)
    sem    = asyncio.Semaphore(concurrency)
    report.total_tested = len(patterns)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        tasks = [_probe(client, target, v, sem) for v in patterns]

        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=35, style="red", complete_style="green"),
            TextColumn("[green]{task.completed}[/green]/[white]{task.total}[/white]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Enumerating API versions", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    report.found.append(result)
                    color = _status_color(result.status)
                    flag  = " [red][DEPRECATED][/red]" if result.deprecated else ""
                    console.print(
                        f"  [{color}]{result.status}[/{color}] "
                        f"[bold white]{result.version}[/bold white]"
                        f"{flag}"
                        + (f" [dim]{' | '.join(result.notes[:2])}[/dim]" if result.notes else "")
                    )
                progress.advance(task_id)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_api_version_enum(
    target:      str,
    patterns:    Optional[list[str]] = None,
    concurrency: int                 = 30,
    proxy:       Optional[str]       = None,
    save_json:   Optional[str]       = None,
) -> APIVersionReport:

    console.print(
        f"\n[bold red][*][/bold red] API Version Enum → "
        f"[bold white]{target}[/bold white]"
    )

    patterns = patterns or VERSION_PATTERNS
    console.print(f"[dim]    Patterns: {len(patterns)}  Concurrency: {concurrency}[/dim]")

    report = asyncio.run(_api_version_async(
        target=target,
        patterns=patterns,
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