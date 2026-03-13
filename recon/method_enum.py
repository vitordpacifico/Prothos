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

ALL_METHODS = [
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
    "HEAD", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH",
    "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
    "SEARCH", "PURGE", "DEBUG",
]

DANGEROUS_METHODS = {"TRACE", "CONNECT", "DEBUG", "PROPFIND", "PROPPATCH",
                     "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "PURGE"}

SUPPORTED_STATUSES = {
    200, 201, 202, 204,
    301, 302, 307, 308,
    400, 401, 403, 407,
    500, 502, 503,
}

UNSUPPORTED_STATUSES = {404, 405, 410, 444, 501}
@dataclass
class MethodResult:
    method:        str
    status:        int
    allowed:       bool
    dangerous:     bool           = False
    cors_origin:   Optional[str]  = None
    allow_header:  Optional[str]  = None
    content_len:   Optional[int]  = None
    response_time: Optional[float]= None
    notes:         list[str]      = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class MethodEnumReport:
    url:           str
    started_at:    str            = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:   Optional[str]  = None
    allowed:       list[MethodResult] = field(default_factory=list)
    dangerous:     list[str]      = field(default_factory=list)
    options_header:Optional[str]  = None
    cors_wildcard: bool           = False
    bypass_found:  bool           = False
    errors:        list[str]      = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["allowed"] = [m.to_dict() for m in self.allowed]
        return d

BYPASS_HEADERS = [
    {"X-Original-URL":        "{path}"},
    {"X-Rewrite-URL":         "{path}"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For":       "127.0.0.1"},
    {"X-Forwarded-For":       "localhost"},
    {"X-Remote-IP":           "127.0.0.1"},
    {"X-Remote-Addr":         "127.0.0.1"},
    {"X-Host":                "localhost"},
    {"X-Originating-IP":      "127.0.0.1"},
    {"X-Real-IP":             "127.0.0.1"},
    {"Referer":               "{url}"},
    {"X-ProxyUser-Ip":        "127.0.0.1"},
]

BYPASS_PATH_VARIATIONS = [
    "{path}/",
    "{path}//",
    "{path}/..",
    "{path}/./",
    "/{path}",
    "//{path}",
    "{path}%20",
    "{path}%09",
    "{path}?",
    "{path}#",
    "{path}..;/",
    "{path};/",
]


async def _try_403_bypass(
    client: httpx.AsyncClient,
    url:    str,
) -> tuple[bool, list[str]]:
    
    parsed   = urlparse(url)
    path     = parsed.path or "/"
    findings = []

    for headers in BYPASS_HEADERS:
        filled = {k: v.replace("{path}", path).replace("{url}", url)
                  for k, v in headers.items()}
        try:
            r = await client.get(url, headers=filled, timeout=8)
            if r.status_code in (200, 201, 202):
                technique = f"Header bypass: {list(filled.keys())[0]}: {list(filled.values())[0]}"
                findings.append(technique)
        except Exception:
            pass

    base = f"{parsed.scheme}://{parsed.netloc}"
    for variation in BYPASS_PATH_VARIATIONS:
        test_path = variation.replace("{path}", path.lstrip("/"))
        test_url  = f"{base}/{test_path}"
        try:
            r = await client.get(test_url, timeout=8)
            if r.status_code in (200, 201, 202):
                findings.append(f"Path bypass: {test_url}")
        except Exception:
            pass

    return bool(findings), findings

async def _test_method(
    client: httpx.AsyncClient,
    url:    str,
    method: str,
    sem:    asyncio.Semaphore,
) -> MethodResult:
    import time
    async with sem:
        try:
            t0 = time.perf_counter()
            r  = await client.request(
                method, url,
                timeout=10,
                content=b"{}" if method in ("POST", "PUT", "PATCH") else None,
                headers={"Content-Type": "application/json"} if method in ("POST", "PUT", "PATCH") else {},
            )
            elapsed = round(time.perf_counter() - t0, 3)

            allowed   = r.status_code in SUPPORTED_STATUSES
            dangerous = method in DANGEROUS_METHODS and allowed
            notes: list[str] = []

            if dangerous:
                notes.append(f" Dangerous method active")
            if r.status_code == 401:
                notes.append(" Auth required")
            if r.status_code == 403:
                notes.append(" Forbidden — bypass possible?")
            if r.status_code in (500, 502, 503):
                notes.append(" Server error on this method")

            cors = r.headers.get("access-control-allow-origin")
            if cors == "*":
                notes.append("🌐 CORS wildcard")

            return MethodResult(
                method=method,
                status=r.status_code,
                allowed=allowed,
                dangerous=dangerous,
                cors_origin=cors,
                allow_header=r.headers.get("allow"),
                content_len=int(r.headers.get("content-length", 0) or len(r.content)),
                response_time=elapsed,
                notes=notes,
            )

        except httpx.TimeoutException:
            return MethodResult(method=method, status=0, allowed=False,
                                notes=["Timeout"])
        except Exception as e:
            return MethodResult(method=method, status=0, allowed=False,
                                notes=[f"Error: {str(e)[:50]}"])


async def _enum_async(
    url:         str,
    methods:     list[str],
    concurrency: int,
    try_bypass:  bool,
    proxy:       Optional[str],
) -> MethodEnumReport:

    report  = MethodEnumReport(url=url)
    sem     = asyncio.Semaphore(concurrency)
    
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
        proxy=proxy,
    ) as client:

        tasks   = [_test_method(client, url, m, sem) for m in methods]
        results = await asyncio.gather(*tasks)

        for r in results:
            if r.allowed:
                report.allowed.append(r)
            if r.dangerous:
                report.dangerous.append(r.method)
            if r.cors_origin == "*":
                report.cors_wildcard = True

        options = next((r for r in results if r.method == "OPTIONS"), None)
        if options and options.allow_header:
            report.options_header = options.allow_header

        forbidden = [r for r in results if r.status == 403]
        if try_bypass and forbidden:
            console.print(f"[dim]    [*] Trying 403 bypass techniques on {url}...[/dim]")
            bypass_found, techniques = await _try_403_bypass(client, url)
            report.bypass_found = bypass_found
            if bypass_found:
                for r in forbidden:
                    r.notes.extend(techniques)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report

def _status_color(status: int) -> str:
    if status < 300:  return "green"
    if status < 400:  return "yellow"
    if status < 500:  return "cyan"
    if status >= 500: return "red"
    return "dim"


def _display_results(report: MethodEnumReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.url}[/bold white]  "
        f"[dim]allowed:[/dim] [green]{len(report.allowed)}[/green]  "
        f"[dim]dangerous:[/dim] [red]{len(report.dangerous)}[/red]  "
        + (f"[dim]options header:[/dim] [yellow]{report.options_header}[/yellow]  "
           if report.options_header else "")
        + (f"[bold red]CORS WILDCARD[/bold red]" if report.cors_wildcard else ""),
        title="[bold red]Method Enumeration[/bold red]",
        border_style="red",
    ))

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Method",  style="bold white", width=10)
    table.add_column("Status",  style="bold",       width=7)
    table.add_column("Size",    style="dim",         width=8)
    table.add_column("Time",    style="dim",         width=8)
    table.add_column("CORS",    style="yellow",      width=10)
    table.add_column("Notes",   style="yellow",      min_width=30)

    all_results = sorted(report.allowed, key=lambda x: x.method)
    for r in all_results:
        color  = _status_color(r.status)
        status = f"[{color}]{r.status}[/{color}]"
        size   = f"{r.content_len}b" if r.content_len else "-"
        t      = f"{r.response_time}s" if r.response_time else "-"
        cors   = r.cors_origin or "-"
        notes  = " | ".join(r.notes) if r.notes else "-"
        table.add_row(r.method, status, size, t, cors, notes)

    console.print(table)

    if report.dangerous:
        console.print(f"\n[bold red][!] DANGEROUS METHODS ACTIVE: {', '.join(report.dangerous)}[/bold red]")

    if report.cors_wildcard:
        console.print(f"[bold red][!] CORS WILDCARD — Access-Control-Allow-Origin: *[/bold red]")

    if report.bypass_found:
        console.print(f"[bold red][!] 403 BYPASS FOUND — check notes above[/bold red]")

    console.print()

def enum_methods(
    url:         str,
    methods:     list[str]     = None,
    concurrency: int           = 20,
    try_bypass:  bool          = True,
    proxy:       Optional[str] = None,
    save_json:   Optional[str] = None,
) -> MethodEnumReport:

    console.print(f"\n[bold red][*][/bold red] Method enumeration → [bold white]{url}[/bold white]")

    methods = methods or ALL_METHODS
    console.print(f"[dim]    Testing {len(methods)} methods  "
                  f"Bypass: {try_bypass}  Concurrency: {concurrency}[/dim]\n")

    report = asyncio.run(_enum_async(
        url=url,
        methods=methods,
        concurrency=concurrency,
        try_bypass=try_bypass,
        proxy=proxy,
    ))

    _display_results(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save JSON: {e}[/red]")

    return report