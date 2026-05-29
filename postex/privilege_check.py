import asyncio
import json
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

ADMIN_PATHS: list[str] = [
    "/admin", "/admin/", "/admin/dashboard", "/admin/users", "/admin/settings",
    "/administrator", "/api/admin", "/api/admin/users", "/api/v1/admin",
    "/manage", "/management", "/console", "/dashboard/admin", "/users",
    "/api/users", "/api/users/all", "/settings/users", "/config", "/api/config",
    "/internal", "/api/internal", "/staff", "/superuser", "/root", "/system",
    "/api/v1/users", "/api/accounts", "/billing/admin", "/audit", "/logs",
]

ESCALATION_PARAMS: list[dict] = [
    {"admin": "true"}, {"is_admin": "true"}, {"isAdmin": "1"}, {"role": "admin"},
    {"role": "administrator"}, {"user_role": "admin"}, {"access_level": "9"},
    {"privilege": "admin"}, {"superuser": "1"}, {"debug": "true"},
]

DENY_MARKERS: list[str] = [
    "access denied", "forbidden", "unauthorized", "not authorized",
    "permission denied", "you do not have", "login required", "please log in",
    "403", "not allowed",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class PrivilegeFinding:
    kind:       str
    location:   str
    status:     int
    detail:     str
    severity:   str          = "high"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class PrivilegeReport:
    target:      str
    started_at:  str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None
    authenticated: bool                   = False
    findings:    list[PrivilegeFinding]   = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    @property
    def high(self) -> list[PrivilegeFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _looks_denied(text: str, status: int) -> bool:
    if status in (401, 403, 404):
        return True
    low = text[:5000].lower()
    return any(m in low for m in DENY_MARKERS)


async def _check_admin_paths(client, root, sem, report):
    async def _one(path):
        url = urljoin(root, path)
        async with sem:
            try:
                r = await client.get(url, timeout=12)
            except Exception:
                return
            if r.status_code in (200, 201) and not _looks_denied(r.text, r.status_code):
                f = PrivilegeFinding(
                    kind="Broken access control",
                    location=url, status=r.status_code,
                    detail="Admin-only endpoint reachable with current (non-admin) credentials",
                    severity="high",
                )
                report.findings.append(f)
                _print_finding(f)

    await asyncio.gather(*[_one(p) for p in ADMIN_PATHS])


async def _check_escalation(client, target, sem, report):
    try:
        base = await client.get(target, timeout=12)
        base_status, base_len = base.status_code, len(base.text)
    except Exception:
        return

    async def _one(params):
        async with sem:
            try:
                r = await client.get(target, params=params, timeout=12)
            except Exception:
                return
            if r.status_code in (200, 201) and abs(len(r.text) - base_len) > 300 and not _looks_denied(r.text, r.status_code):
                key = next(iter(params))
                f = PrivilegeFinding(
                    kind="Privilege param tampering",
                    location=f"{target} [{key}={params[key]}]", status=r.status_code,
                    detail=f"Response changes when sending '{key}={params[key]}' — possible role escalation via parameter",
                    severity="medium",
                )
                report.findings.append(f)
                _print_finding(f)

    await asyncio.gather(*[_one(p) for p in ESCALATION_PARAMS])


def _print_finding(f: PrivilegeFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.kind}[/bold white] → "
        f"[yellow]{f.location}[/yellow] [dim]({f.status})[/dim]"
    )


def _display(report: PrivilegeReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]auth:[/dim] {'token/cookie' if report.authenticated else 'none'}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Privilege Check — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No access-control issues found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Kind",      style="cyan", width=26)
    table.add_column("Status",    style="dim", width=7)
    table.add_column("Location",  style="yellow", min_width=30)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.kind, str(f.status), f.location[:50])

    console.print(table)
    console.print()


async def _priv_async(target, token, scheme, cookies, concurrency, proxy) -> PrivilegeReport:
    report = PrivilegeReport(target=target)
    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"
    sem = asyncio.Semaphore(concurrency)

    headers = {"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"}
    if token:
        headers["Authorization"] = f"{scheme} {token}"
        report.authenticated = True
    cookie_jar = {}
    if cookies:
        report.authenticated = True
        for pair in cookies.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookie_jar[k.strip()] = v.strip()

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, proxy=proxy,
        headers=headers, cookies=cookie_jar,
    ) as client:
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=35, style="red", complete_style="green"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as progress:
            progress.add_task("Checking privileges...", total=None)
            await _check_admin_paths(client, root, sem, report)
            await _check_escalation(client, target, sem, report)

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_privilege_check(
    target:      str,
    token:       Optional[str]  = None,
    auth_scheme: str            = "Bearer",
    cookies:     Optional[str]  = None,
    concurrency: int            = 12,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> PrivilegeReport:

    console.print(f"\n[bold red][*][/bold red] Privilege Check → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Admin paths: {len(ADMIN_PATHS)}  Escalation params: {len(ESCALATION_PARAMS)}[/dim]")

    report = asyncio.run(_priv_async(target, token, auth_scheme, cookies, concurrency, proxy))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
