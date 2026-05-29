import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

CANARY = "prth0s-cache-canary.example"

UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Port",
    "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override", "Forwarded",
    "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For",
]

CACHE_HINT_HEADERS = ["x-cache", "cf-cache-status", "age", "x-cache-hits",
                      "x-served-by", "x-varnish", "cache-control"]

SEVERITY_COLOR = {
    "critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "cyan",
}


@dataclass
class CacheFinding:
    kind:       str
    header:     str
    detail:     str
    cacheable:  bool
    severity:   str          = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class CachePoisoningReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    cacheable:   bool                = False
    findings:    list[CacheFinding]  = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def high(self) -> list[CacheFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _cacheable(headers: dict) -> bool:
    cc = headers.get("cache-control", "").lower()
    if "no-store" in cc or "private" in cc:
        return False
    if "public" in cc or "max-age" in cc or "s-maxage" in cc:
        return True
    return any(h in headers for h in ("x-cache", "cf-cache-status", "age", "x-varnish"))


def _add(report, kind, header, detail, cacheable, severity):
    f = CacheFinding(kind=kind, header=header, detail=detail, cacheable=cacheable, severity=severity)
    report.findings.append(f)
    _print_finding(f)


async def _test_header(client, target, header, base_cacheable, sem, report):
    async with sem:
        try:
            r = await client.get(target, headers={header: CANARY}, timeout=12)
        except Exception:
            return
        resp_headers = {k.lower(): v for k, v in r.headers.items()}
        cacheable = _cacheable(resp_headers)

        reflected_body = CANARY in r.text
        reflected_loc = CANARY in resp_headers.get("location", "")

        if reflected_loc:
            sev = "high" if cacheable else "medium"
            _add(report, "Unkeyed input reflected (Location)", header,
                 f"{header} reflected into redirect Location", cacheable, sev)
        elif reflected_body:
            sev = "high" if cacheable else "low"
            _add(report, "Unkeyed input reflected (body)", header,
                 f"{header} value reflected into response body", cacheable, sev)


def _print_finding(f: CacheFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    cache = "[red]cacheable[/red]" if f.cacheable else "[dim]not cached[/dim]"
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.header}[/bold white] → [yellow]{f.detail}[/yellow] {cache}"
    )


def _display(report: CachePoisoningReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]cacheable:[/dim] {'yes' if report.cacheable else 'unknown'}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Cache Poisoning — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No cache poisoning vectors found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Header",   style="cyan", width=22)
    table.add_column("Cached",   width=10)
    table.add_column("Detail",   style="yellow", min_width=30)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.header,
                      "yes" if f.cacheable else "no", f.detail[:45])

    console.print(table)
    console.print()
    console.print("[dim]    Note: confirm the poisoned response is actually served from cache before reporting.[/dim]\n")


async def _cache_async(target, concurrency, proxy) -> CachePoisoningReport:
    report = CachePoisoningReport(target=target)
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as progress:
            progress.add_task("Testing cache poisoning...", total=None)
            try:
                base = await client.get(target, timeout=12)
                report.cacheable = _cacheable({k.lower(): v for k, v in base.headers.items()})
            except Exception as e:
                report.errors.append(str(e)[:100])

            await asyncio.gather(*[
                _test_header(client, target, h, report.cacheable, sem, report)
                for h in UNKEYED_HEADERS
            ])

    report.findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_cache_poisoning(
    target:      str,
    concurrency: int            = 8,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> CachePoisoningReport:

    console.print(f"\n[bold red][*][/bold red] Cache Poisoning → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Unkeyed headers: {len(UNKEYED_HEADERS)}[/dim]")

    report = asyncio.run(_cache_async(target, concurrency, proxy))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
