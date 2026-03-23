import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

@dataclass
class ParamResult:
    param:         str
    url:           str
    method:        str
    status:        int
    content_len:   int                = 0
    response_time: float              = 0.0
    reflected:     bool               = False
    interesting:   bool               = False
    diff_from_base: bool              = False
    notes:         list[str]          = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ParamReport:
    target:        str
    started_at:    str                      = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:   Optional[str]           = None
    total_tested:  int                      = 0
    found:         list[ParamResult]        = field(default_factory=list)
    errors:        list[str]               = field(default_factory=list)

    @property
    def interesting(self) -> list[ParamResult]:
        return [r for r in self.found if r.interesting]

    @property
    def reflected(self) -> list[ParamResult]:
        return [r for r in self.found if r.reflected]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["found"] = [r.to_dict() for r in self.found]
        return d

DEFAULT_PARAMS = [
    "token", "api_key", "apikey", "api-key", "key", "secret",
    "auth", "authorization", "access_token", "refresh_token",
    "jwt", "session", "session_id", "sid", "csrf", "csrf_token",

    "id", "user_id", "uid", "user", "username", "email",
    "account", "account_id", "profile", "member", "member_id",
    "customer", "customer_id", "client", "client_id",

    "action", "cmd", "command", "exec", "execute", "run",
    "method", "operation", "func", "function", "callback",

    "data", "query", "q", "search", "filter", "sort",
    "order", "orderby", "order_by", "limit", "offset",
    "page", "per_page", "size", "count", "from", "to",
    "start", "end", "cursor", "next", "prev",

    "file", "filename", "path", "dir", "folder", "url",
    "uri", "href", "src", "source", "dest", "destination",
    "redirect", "return", "return_url", "next_url", "goto",
    "target", "ref", "referrer", "origin",

    "debug", "test", "mode", "env", "environment",
    "format", "type", "version", "v", "lang", "locale",
    "timezone", "tz", "currency", "country", "region",

    "content", "body", "message", "text", "title", "name",
    "description", "comment", "note", "tag", "label",
    "category", "status", "state", "code", "value",

    "parent", "parent_id", "child", "child_id", "group",
    "group_id", "role", "permission", "scope", "access",

    "fields", "expand", "include", "exclude", "embed",
    "populate", "select", "where", "having",

    "upload", "file_type", "mime", "extension",

    "callback_url", "webhook", "notify", "subscribe",
    "confirm", "verify", "validate", "check",
]

async def _get_baseline(
    client: httpx.AsyncClient,
    url:    str,
    method: str,
) -> tuple[int, int, str]:
    try:
        if method == "GET":
            r = await client.get(url, timeout=10)
        else:
            r = await client.post(url, timeout=10)
        return r.status_code, len(r.content), r.text[:500]
    except Exception:
        return 0, 0, ""

CANARY = "pr0th0scanary"

async def _probe(
    client:   httpx.AsyncClient,
    url:      str,
    param:    str,
    method:   str,
    sem:      asyncio.Semaphore,
    baseline: tuple[int, int, str],
) -> Optional[ParamResult]:

    baseline_status, baseline_len, baseline_body = baseline

    async with sem:
        import time
        try:
            t0 = time.perf_counter()

            if method == "GET":
                parsed  = urlparse(url)
                new_url = urlunparse(parsed._replace(
                    query=f"{parsed.query}&{param}={CANARY}" if parsed.query
                          else f"{param}={CANARY}"
                ))
                r = await client.get(new_url, timeout=10)
            else:
                r = await client.post(
                    url,
                    data={param: CANARY},
                    timeout=10,
                )

            elapsed = round(time.perf_counter() - t0, 3)
            body    = r.text
            headers = {k.lower(): v for k, v in r.headers.items()}

            status_diff = r.status_code != baseline_status
            len_diff    = abs(len(r.content) - baseline_len) > 100
            body_diff   = body[:500] != baseline_body

            diff = status_diff or (len_diff and body_diff)

            if not diff:
                return None

            notes       = []
            interesting = False
            reflected   = False

            if CANARY in body:
                reflected   = True
                interesting = True
                notes.append("Reflected in response")

            if r.status_code in (200, 201):
                interesting = True
                notes.append("200 OK")
            elif r.status_code in (401, 403):
                notes.append("Auth required")
                interesting = True
            elif r.status_code == 500:
                notes.append("Server error")
                interesting = True
            elif r.status_code in (301, 302, 307, 308):
                loc = headers.get("location", "")
                notes.append(f"Redirect → {loc[:40]}")

            if len_diff:
                delta = len(r.content) - baseline_len
                notes.append(f"Size delta: {delta:+d}b")

            if elapsed > 3.0:
                notes.append(f"Slow ({elapsed:.1f}s)")

            return ParamResult(
                param=param,
                url=str(r.url) if method == "GET" else url,
                method=method,
                status=r.status_code,
                content_len=len(r.content),
                response_time=elapsed,
                reflected=reflected,
                interesting=interesting,
                diff_from_base=diff,
                notes=notes,
            )

        except httpx.TimeoutException:
            return None
        except Exception:
            return None

def _status_color(status: int) -> str:
    if status < 300: return "green"
    if status < 400: return "yellow"
    if status < 500: return "cyan"
    return "red"


def _display(report: ParamReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]tested:[/dim] {report.total_tested}  "
        f"[dim]found:[/dim] [green]{len(report.found)}[/green]  "
        f"[dim]interesting:[/dim] [yellow]{len(report.interesting)}[/yellow]  "
        f"[dim]reflected:[/dim] [red]{len(report.reflected)}[/red]",
        title="[bold red]Parameter Discovery — Summary[/bold red]",
        border_style="red",
    ))

    if not report.found:
        console.print("[dim]    No parameters discovered.[/dim]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold red",
        border_style="dim",
    )
    table.add_column("Status",    width=8)
    table.add_column("Method",    width=7)
    table.add_column("Param",     width=20, style="cyan")
    table.add_column("Size",      width=8,  style="dim")
    table.add_column("Time",      width=7,  style="dim")
    table.add_column("Notes",     min_width=25, style="yellow")

    for r in sorted(report.found, key=lambda x: (not x.interesting, x.param)):
        color    = _status_color(r.status)
        refl_tag = " [red][R][/red]" if r.reflected else ""
        table.add_row(
            f"[{color}]{r.status}[/{color}]",
            r.method,
            r.param + refl_tag,
            f"{r.content_len}b",
            f"{r.response_time}s",
            " | ".join(r.notes[:2]) if r.notes else "-",
        )

    console.print(table)

    if report.reflected:
        console.print(f"\n[bold red][!] Reflected params ({len(report.reflected)}) — potential XSS:[/bold red]")
        for r in report.reflected:
            c = _status_color(r.status)
            console.print(f"    [red]→[/red] [{c}]{r.status}[/{c}] {r.param}")

    console.print()

async def _param_async(
    target:      str,
    wordlist:    list[str],
    methods:     list[str],
    concurrency: int,
    proxy:       Optional[str],
) -> ParamReport:

    report = ParamReport(target=target)
    sem    = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        all_tasks = []
        for method in methods:
            console.print(f"[dim]    Getting {method} baseline...[/dim]")
            baseline = await _get_baseline(client, target, method)
            console.print(
                f"[dim]    Baseline {method}: "
                f"status={baseline[0]} len={baseline[1]}b[/dim]"
            )
            for param in wordlist:
                all_tasks.append((param, method, baseline))

        report.total_tested = len(all_tasks)

        tasks = [
            _probe(client, target, param, method, sem, baseline)
            for param, method, baseline in all_tasks
        ]

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
            task_id = progress.add_task("Discovering parameters", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    report.found.append(result)
                    color    = _status_color(result.status)
                    refl_tag = " [red][REFLECTED][/red]" if result.reflected else ""
                    console.print(
                        f"  [{color}]{result.status}[/{color}] "
                        f"[cyan]{result.param}[/cyan] "
                        f"[dim]{result.method}[/dim]"
                        f"{refl_tag}"
                        + (f" [dim]{' | '.join(result.notes[:1])}[/dim]" if result.notes else "")
                    )
                progress.advance(task_id)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_parameter_discovery(
    target:      str,
    wordlist:    Optional[list[str]] = None,
    wordlist_path: Optional[str]     = None,
    methods:     list[str]           = None,
    concurrency: int                 = 30,
    proxy:       Optional[str]       = None,
    save_json:   Optional[str]       = None,
) -> ParamReport:
    
    console.print(
        f"\n[bold red][*][/bold red] Parameter Discovery → "
        f"[bold white]{target}[/bold white]"
    )

    if wordlist_path:
        try:
            from utils.wordlist_loader import load_wordlist
            wordlist = load_wordlist(wordlist_path)
        except Exception as e:
            console.print(f"[red][!] Failed to load wordlist: {e}[/red]")
            wordlist = DEFAULT_PARAMS
    elif not wordlist:
        wordlist = DEFAULT_PARAMS

    methods = methods or ["GET", "POST"]

    console.print(
        f"[dim]    Params: {len(wordlist)}  "
        f"Methods: {', '.join(methods)}  "
        f"Concurrency: {concurrency}[/dim]"
    )

    report = asyncio.run(_param_async(
        target=target,
        wordlist=wordlist,
        methods=methods,
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