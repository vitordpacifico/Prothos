import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

SENSITIVE_PARAMS = {"price", "amount", "qty", "quantity", "total", "cost", "balance",
                    "credit", "discount", "value", "sum", "count", "limit", "id",
                    "user_id", "account", "points", "stock"}

BOUNDARY_VALUES = ["-1", "0", "-0.01", "999999999", "1e9", "0.00001", "4294967296"]

SEVERITY_COLOR = {
    "critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "cyan",
}


@dataclass
class LogicFinding:
    kind:       str
    location:   str
    detail:     str
    severity:   str          = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class BusinessLogicReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    params:      list[str]           = field(default_factory=list)
    findings:    list[LogicFinding]  = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def high(self) -> list[LogicFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _set_param(url, param, value):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _add(report, kind, location, detail, severity):
    f = LogicFinding(kind=kind, location=location, detail=detail, severity=severity)
    report.findings.append(f)
    _print_finding(f)


def _err(text, status):
    if status >= 500:
        return True
    low = text[:3000].lower()
    return any(m in low for m in ("invalid", "error", "not allowed", "must be", "negative", "out of range"))


async def _test_numeric(client, target, param, base_status, base_len, report):
    sensitive = param.lower() in SENSITIVE_PARAMS
    for val in BOUNDARY_VALUES:
        try:
            r = await client.get(_set_param(target, param, val), timeout=12)
        except Exception:
            continue
        if r.status_code in (200, 201) and not _err(r.text, r.status_code):
            if val.startswith("-") or val == "0":
                sev = "high" if sensitive else "medium"
                _add(report, "Boundary value accepted", f"{target} [{param}={val}]",
                     f"Negative/zero accepted on {'sensitive ' if sensitive else ''}param '{param}' "
                     f"without validation", sev)
                return
            if val in ("999999999", "1e9", "4294967296"):
                sev = "medium" if sensitive else "low"
                _add(report, "Overflow value accepted", f"{target} [{param}={val}]",
                     f"Very large value accepted on '{param}'", sev)
                return


async def _test_rate_limit(client, target, report):
    statuses = []
    t0 = time.perf_counter()
    try:
        results = await asyncio.gather(*[client.get(target, timeout=10) for _ in range(20)],
                                       return_exceptions=True)
    except Exception:
        return
    for r in results:
        if isinstance(r, httpx.Response):
            statuses.append(r.status_code)
    if statuses and 429 not in statuses and all(s < 400 for s in statuses):
        elapsed = time.perf_counter() - t0
        _add(report, "No rate limiting", target,
             f"20 rapid requests all succeeded ({elapsed:.1f}s), no 429 — abuse/automation risk", "low")


def _print_finding(f: LogicFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.kind}[/bold white] → [yellow]{f.detail}[/yellow]"
    )


def _display(report: BusinessLogicReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]params:[/dim] {len(report.params)}  "
        f"[dim]candidates:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Business Logic — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No business-logic candidates found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Kind",     style="cyan", width=24)
    table.add_column("Detail",   style="yellow", min_width=35)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.kind, f.detail[:50])

    console.print(table)
    console.print()
    console.print("[dim]    Note: business-logic flaws need manual validation — these are candidates, not confirmed.[/dim]\n")


async def _logic_async(target, concurrency, proxy) -> BusinessLogicReport:
    report = BusinessLogicReport(target=target)
    params = list(parse_qs(urlparse(target).query).keys())
    report.params = params
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as progress:
            progress.add_task("Testing business logic...", total=None)
            try:
                base = await client.get(target, timeout=12)
                base_status, base_len = base.status_code, len(base.text)
            except Exception as e:
                report.errors.append(str(e)[:100])
                base_status, base_len = 0, 0

            async def _one(p):
                async with sem:
                    await _test_numeric(client, target, p, base_status, base_len, report)

            if params:
                await asyncio.gather(*[_one(p) for p in params])
            await _test_rate_limit(client, target, report)

    report.findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_business_logic(
    target:      str,
    concurrency: int            = 8,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> BusinessLogicReport:

    console.print(f"\n[bold red][*][/bold red] Business Logic → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Params: {len(list(parse_qs(urlparse(target).query).keys()))}  "
                  f"Boundary values + rate-limit probe[/dim]")

    report = asyncio.run(_logic_async(target, concurrency, proxy))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
