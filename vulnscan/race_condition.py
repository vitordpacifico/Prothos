import asyncio
import json
import hashlib
from collections import Counter
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

CRITICAL_PATHS: list[str] = [
    "/checkout", "/api/checkout", "/cart/checkout", "/order", "/api/order",
    "/coupon/redeem", "/api/coupon", "/apply-coupon", "/redeem", "/gift-card/redeem",
    "/password/reset", "/api/password/reset", "/transfer", "/api/transfer",
    "/withdraw", "/api/withdraw", "/vote", "/api/vote", "/like", "/follow",
    "/api/v1/payment", "/balance/transfer", "/account/transfer",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class RaceFinding:
    url:           str
    method:        str
    requests:      int
    status_spread: dict
    success_count: int
    distinct_bodies: int
    evidence:      str          = ""
    severity:      str          = "high"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class RaceReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    endpoints:   list[str]           = field(default_factory=list)
    findings:    list[RaceFinding]   = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def high(self) -> list[RaceFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


async def _fire_one(client, method, url, data, json_body, gate) -> Optional[tuple[int, int, str]]:
    await gate.wait()
    try:
        r = await client.request(method, url, data=data, json=json_body, timeout=20)
        body_hash = hashlib.md5(r.text.encode("utf-8", "replace")).hexdigest()
        return r.status_code, len(r.text), body_hash
    except Exception:
        return None


async def _race_endpoint(client, method, url, data, json_body, n) -> Optional[RaceFinding]:
    gate = asyncio.Event()
    tasks = [
        asyncio.create_task(_fire_one(client, method, url, data, json_body, gate))
        for _ in range(n)
    ]
    await asyncio.sleep(0.05)
    gate.set()
    results = await asyncio.gather(*tasks)

    results = [r for r in results if r is not None]
    if len(results) < 2:
        return None

    statuses = [r[0] for r in results]
    bodies   = {r[2] for r in results}
    status_spread = dict(Counter(statuses))
    success_count = sum(1 for s in statuses if 200 <= s < 300)

    status_varied = len(set(statuses)) > 1
    multi_success = success_count > 1
    body_varied   = len(bodies) > 1

    if (status_varied or body_varied) and success_count >= 1:
        sev = "high" if multi_success and (status_varied or body_varied) else "medium"
        evidence = (f"{success_count}/{len(results)} succeeded, "
                    f"statuses={status_spread}, distinct_bodies={len(bodies)}")
        f = RaceFinding(
            url=url, method=method, requests=len(results),
            status_spread=status_spread, success_count=success_count,
            distinct_bodies=len(bodies), evidence=evidence, severity=sev,
        )
        _print_finding(f)
        return f
    return None


def _print_finding(f: RaceFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.url}[/bold white] → "
        f"[yellow]{f.evidence}[/yellow]"
    )


def _display(report: RaceReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]endpoints:[/dim] {len(report.endpoints)}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Race Condition — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No race conditions detected.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Endpoint",  style="bold white", min_width=30)
    table.add_column("Method",    style="cyan", width=8)
    table.add_column("Success",   style="dim", width=9)
    table.add_column("Evidence",  style="yellow", min_width=28)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.url, f.method, f"{f.success_count}/{f.requests}", f.evidence[:42],
        )

    console.print(table)
    console.print()
    console.print("[dim]    Note: concurrency heuristic — confirm the business impact manually.[/dim]\n")


def _build_endpoints(target: str, probe_paths: bool) -> list[str]:
    parsed = urlparse(target)
    if parsed.path and parsed.path != "/":
        return [target]
    if probe_paths:
        root = f"{parsed.scheme}://{parsed.netloc}"
        return [urljoin(root, p) for p in CRITICAL_PATHS]
    return [target]


async def _race_async(target, method, data, json_body, n, probe_paths,
                      token, scheme, cookies, concurrency, proxy) -> RaceReport:
    report = RaceReport(target=target)
    endpoints = _build_endpoints(target, probe_paths)
    report.endpoints = endpoints

    headers = {"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"}
    if token:
        headers["Authorization"] = f"{scheme} {token}"
    cookie_jar = {}
    if cookies:
        for pair in cookies.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookie_jar[k.strip()] = v.strip()

    limits = httpx.Limits(max_connections=n + 10, max_keepalive_connections=n + 10)
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        proxy=proxy,
        headers=headers,
        cookies=cookie_jar,
        limits=limits,
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
            task_id = progress.add_task("Racing endpoints...", total=len(endpoints))

            async def _guarded(ep):
                async with sem:
                    return await _race_endpoint(client, method, ep, data, json_body, n)

            tasks = [_guarded(ep) for ep in endpoints]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    report.findings.append(result)
                progress.advance(task_id, 1)

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_race_condition(
    target:        str,
    method:        str                 = "POST",
    data:          Optional[dict]      = None,
    json_body:     Optional[dict]      = None,
    n:             int                 = 20,
    probe_paths:   bool                = False,
    token:         Optional[str]       = None,
    auth_scheme:   str                 = "Bearer",
    cookies:       Optional[str]       = None,
    concurrency:   int                 = 5,
    proxy:         Optional[str]       = None,
    save_json:     Optional[str]       = None,
) -> RaceReport:

    console.print(f"\n[bold red][*][/bold red] Race Condition → [bold white]{target}[/bold white]")
    eps = _build_endpoints(target, probe_paths)
    console.print(f"[dim]    Endpoints: {len(eps)}  Concurrent requests each: {n}  Method: {method}[/dim]")

    report = asyncio.run(_race_async(
        target=target,
        method=method.upper(),
        data=data,
        json_body=json_body,
        n=n,
        probe_paths=probe_paths,
        token=token,
        scheme=auth_scheme,
        cookies=cookies,
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
