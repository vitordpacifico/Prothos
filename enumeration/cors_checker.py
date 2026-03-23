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

@dataclass
class CORSResult:
    url:                  str
    origin_tested:        str
    status:               int                = 0
    acao:                 Optional[str]      = None
    acac:                 Optional[str]      = None
    acam:                 Optional[str]      = None
    acah:                 Optional[str]      = None
    vulnerable:           bool               = False
    severity:             str                = "info"
    issue:                str                = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class CORSReport:
    target:      str
    started_at:  str                          = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]               = None
    results:     list[CORSResult]            = field(default_factory=list)
    findings:    list[CORSResult]            = field(default_factory=list)
    errors:      list[str]                   = field(default_factory=list)

    @property
    def vulnerable(self) -> list[CORSResult]:
        return [r for r in self.results if r.vulnerable]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["results"]  = [r.to_dict() for r in self.results]
        d["findings"] = [r.to_dict() for r in self.findings]
        return d

def _build_origins(target: str) -> list[tuple[str, str]]:
    parsed = urlparse(target)
    domain = parsed.netloc
    scheme = parsed.scheme

    base = f"{scheme}://{domain}"
    root = domain.split(".")[-2] if domain.count(".") >= 1 else domain

    return [
        ("wildcard_reflection",   "https://evil.com"),
        ("null_origin",           "null"),
        ("subdomain_prefix",      f"https://evil.{domain}"),
        ("domain_suffix",         f"https://evil{domain}"),
        ("domain_prefix",         f"https://{domain}.evil.com"),
        ("http_downgrade",        f"http://{domain}"),
        ("trusted_subdomain",     f"https://sub.{domain}"),
        ("partial_match",         f"https://{root}evil.com"),
        ("unicode_bypass",        f"https://{domain}\u2100evil.com"),
        ("self_origin",           base),
    ]

def _analyze(result: CORSResult, origin: str, label: str) -> CORSResult:
    acao = result.acao or ""
    acac = result.acac or ""

    if acao == "*":
        result.vulnerable = True
        result.severity   = "medium"
        result.issue      = "Wildcard ACAO (*) — credentialed requests blocked but still insecure"
        return result

    if acao == origin and acac.lower() == "true":
        if label == "null_origin":
            result.vulnerable = True
            result.severity   = "high"
            result.issue      = "Null origin reflected with credentials — sandbox bypass possible"
        elif label in ("wildcard_reflection", "subdomain_prefix",
                       "domain_suffix", "domain_prefix", "partial_match"):
            result.vulnerable = True
            result.severity   = "critical"
            result.issue      = f"Origin reflected ({label}) with ACAC: true — full CORS exploit"
        elif label == "http_downgrade":
            result.vulnerable = True
            result.severity   = "high"
            result.issue      = "HTTP origin accepted with credentials — protocol downgrade attack"
        else:
            result.vulnerable = True
            result.severity   = "medium"
            result.issue      = f"Origin reflected ({label}) with credentials"
        return result

    if acao == origin and acac.lower() != "true":
        if label not in ("self_origin", "trusted_subdomain"):
            result.vulnerable = True
            result.severity   = "low"
            result.issue      = f"Origin reflected ({label}) without credentials"

    return result

async def _probe(
    client: httpx.AsyncClient,
    url:    str,
    origin: str,
    label:  str,
    sem:    asyncio.Semaphore,
) -> CORSResult:

    result = CORSResult(url=url, origin_tested=origin)

    async with sem:
        try:
            r = await client.options(
                url,
                headers={"Origin": origin},
                timeout=10,
            )
            headers = {k.lower(): v for k, v in r.headers.items()}

            result.status = r.status_code
            result.acao   = headers.get("access-control-allow-origin")
            result.acac   = headers.get("access-control-allow-credentials")
            result.acam   = headers.get("access-control-allow-methods")
            result.acah   = headers.get("access-control-allow-headers")

            if result.acao:
                result = _analyze(result, origin, label)

        except httpx.TimeoutException:
            result.issue = "timeout"
        except Exception as e:
            result.issue = str(e)[:60]

    return result

def _severity_color(sev: str) -> str:
    return {
        "critical": "bold red",
        "high":     "red",
        "medium":   "yellow",
        "low":      "dim",
        "info":     "cyan",
    }.get(sev, "white")


def _display(report: CORSReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]tested:[/dim] {len(report.results)}  "
        f"[dim]vulnerable:[/dim] [red]{len(report.vulnerable)}[/red]",
        title="[bold red]CORS Checker — Summary[/bold red]",
        border_style="red",
    ))

    if not report.vulnerable:
        console.print("[dim]    No CORS misconfigurations found.[/dim]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold red",
        border_style="dim",
    )
    table.add_column("Severity",  width=10)
    table.add_column("Origin",    width=35)
    table.add_column("ACAO",      width=35)
    table.add_column("ACAC",      width=6)
    table.add_column("Issue",     min_width=30)

    for r in report.vulnerable:
        color = _severity_color(r.severity)
        table.add_row(
            f"[{color}]{r.severity.upper()}[/{color}]",
            r.origin_tested[:35],
            r.acao or "-",
            r.acac or "-",
            r.issue,
        )

    console.print(table)
    console.print()

async def _cors_async(
    target:      str,
    concurrency: int,
    proxy:       Optional[str],
) -> CORSReport:

    report  = CORSReport(target=target)
    origins = _build_origins(target)
    sem     = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:
        tasks = [
            _probe(client, target, origin, label, sem)
            for label, origin in origins
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, CORSResult):
            report.results.append(r)
            if r.vulnerable:
                report.findings.append(r)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_cors_checker(
    target:      str,
    concurrency: int          = 10,
    proxy:       Optional[str]= None,
    save_json:   Optional[str]= None,
) -> CORSReport:
    console.print(f"\n[bold red][*][/bold red] CORS Checker → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Testing {len(_build_origins(target))} origin variations...[/dim]")

    report = asyncio.run(_cors_async(
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