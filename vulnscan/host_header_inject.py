import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

EVIL_HOST = "prothos-hhi-canary.example"

INJECTION_VECTORS: list[dict] = [
    {"name": "Host override",            "headers": {"Host": EVIL_HOST}},
    {"name": "Host with port",           "headers": {"Host": f"{EVIL_HOST}:80"}},
    {"name": "X-Forwarded-Host",         "headers": {"X-Forwarded-Host": EVIL_HOST}},
    {"name": "X-Host",                   "headers": {"X-Host": EVIL_HOST}},
    {"name": "X-Forwarded-Server",       "headers": {"X-Forwarded-Server": EVIL_HOST}},
    {"name": "X-HTTP-Host-Override",     "headers": {"X-HTTP-Host-Override": EVIL_HOST}},
    {"name": "Forwarded host",           "headers": {"Forwarded": f"host={EVIL_HOST}"}},
    {"name": "X-Forwarded-Host dup",     "headers": {"X-Forwarded-Host": EVIL_HOST, "X-Forwarded-For": EVIL_HOST}},
    {"name": "Absolute-URI",             "headers": {"Host": EVIL_HOST}, "absolute": True},
    {"name": "Host line wrapping",       "headers": {"X-Forwarded-Host": EVIL_HOST, "X-Original-Host": EVIL_HOST}},
]

RESET_PATHS: list[str] = [
    "/password/reset", "/reset-password", "/forgot-password", "/forgot",
    "/account/recover", "/api/password/reset", "/users/password",
    "/auth/forgot-password", "/reset", "/recover",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class HostHeaderFinding:
    url:         str
    vector:      str
    context:     str
    status:      int          = 0
    evidence:    str          = ""
    severity:    str          = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class HostHeaderReport:
    target:      str
    started_at:  str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None
    findings:    list[HostHeaderFinding]  = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    @property
    def high(self) -> list[HostHeaderFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _reflected_in_body(body: str) -> Optional[str]:
    idx = body.lower().find(EVIL_HOST)
    if idx == -1:
        return None
    snippet = body[max(0, idx - 40): idx + len(EVIL_HOST) + 40]
    if re.search(rf'(?:href|src|action)\s*=\s*["\']?[^"\'>]*{re.escape(EVIL_HOST)}', body, re.IGNORECASE):
        return f"reflected in attribute: ...{snippet.strip()}..."
    if re.search(rf'https?://{re.escape(EVIL_HOST)}', body, re.IGNORECASE):
        return f"reflected as absolute URL: ...{snippet.strip()}..."
    return f"reflected in body: ...{snippet.strip()}..."


def _reflected_in_headers(headers: dict) -> Optional[str]:
    for k, v in headers.items():
        if EVIL_HOST in str(v).lower():
            return f"reflected in response header {k}: {v[:80]}"
    return None


async def _test_vector(
    client:  httpx.AsyncClient,
    url:     str,
    vector:  dict,
    sem:     asyncio.Semaphore,
) -> list[HostHeaderFinding]:

    findings: list[HostHeaderFinding] = []
    parsed = urlparse(url)

    async with sem:
        try:
            request_url = url
            if vector.get("absolute"):
                request_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
            r = await client.get(request_url, headers=vector["headers"], timeout=10)
        except Exception:
            return findings

        resp_headers = {k.lower(): v for k, v in r.headers.items()}
        location = resp_headers.get("location", "")

        if EVIL_HOST in location.lower():
            f = HostHeaderFinding(
                url=url, vector=vector["name"], context="redirect Location",
                status=r.status_code, evidence=f"Location: {location[:90]}", severity="high",
            )
            findings.append(f)
            _print_finding(f)
            return findings

        hdr_hit = _reflected_in_headers(resp_headers)
        if hdr_hit:
            f = HostHeaderFinding(
                url=url, vector=vector["name"], context="response header",
                status=r.status_code, evidence=hdr_hit, severity="high",
            )
            findings.append(f)
            _print_finding(f)
            return findings

        body_hit = _reflected_in_body(r.text)
        if body_hit:
            sev = "high" if "absolute URL" in body_hit or "attribute" in body_hit else "medium"
            f = HostHeaderFinding(
                url=url, vector=vector["name"], context="response body",
                status=r.status_code, evidence=body_hit[:160], severity=sev,
            )
            findings.append(f)
            _print_finding(f)

    return findings


async def _test_reset_poisoning(
    client: httpx.AsyncClient,
    base:   str,
    email:  Optional[str],
    sem:    asyncio.Semaphore,
) -> list[HostHeaderFinding]:

    findings: list[HostHeaderFinding] = []
    if not email:
        return findings

    parsed = urlparse(base)
    root   = f"{parsed.scheme}://{parsed.netloc}"

    async with sem:
        for path in RESET_PATHS:
            target = root + path
            for vector in (INJECTION_VECTORS[0], INJECTION_VECTORS[2], INJECTION_VECTORS[3]):
                try:
                    r = await client.post(
                        target,
                        headers=vector["headers"],
                        data={"email": email, "username": email},
                        timeout=10,
                    )
                except Exception:
                    continue

                resp_headers = {k.lower(): v for k, v in r.headers.items()}
                reflected = (EVIL_HOST in r.text.lower()
                             or any(EVIL_HOST in str(v).lower() for v in resp_headers.values()))
                if r.status_code < 400 and reflected:
                    f = HostHeaderFinding(
                        url=target, vector=f"reset poison ({vector['name']})",
                        context="password reset", status=r.status_code,
                        evidence=f"Host {EVIL_HOST} reflected in reset flow",
                        severity="high",
                    )
                    findings.append(f)
                    _print_finding(f)
    return findings


def _print_finding(f: HostHeaderFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.vector}[/bold white] → "
        f"[yellow]{f.context}[/yellow]  "
        f"[dim]{f.evidence[:60]}[/dim]"
    )


def _display(report: HostHeaderReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Host Header Injection — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No host header injection found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Vector",    style="bold white", width=26)
    table.add_column("Context",   style="cyan", width=18)
    table.add_column("Status",    style="dim", width=7)
    table.add_column("Evidence",  style="yellow", min_width=30)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.vector,
            f.context,
            str(f.status) if f.status else "-",
            f.evidence[:50],
        )

    console.print(table)
    console.print()


async def _hhi_async(
    target:      str,
    reset_email: Optional[str],
    concurrency: int,
    proxy:       Optional[str],
) -> HostHeaderReport:

    report = HostHeaderReport(target=target)
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
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Testing host header...", total=None)

            tasks = [_test_vector(client, target, v, sem) for v in INJECTION_VECTORS]
            for coro in asyncio.as_completed(tasks):
                report.findings.extend(await coro)

            report.findings.extend(
                await _test_reset_poisoning(client, target, reset_email, sem))
            progress.update(task_id, completed=1, total=1)

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_host_header_inject(
    target:      str,
    reset_email: Optional[str]  = None,
    concurrency: int            = 10,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> HostHeaderReport:

    console.print(f"\n[bold red][*][/bold red] Host Header Injection → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Vectors: {len(INJECTION_VECTORS)}  "
                  f"Reset poisoning: {'on' if reset_email else 'off'}[/dim]")

    report = asyncio.run(_hhi_async(
        target=target,
        reset_email=reset_email,
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
