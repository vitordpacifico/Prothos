import asyncio
import json
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

EVIL_REDIRECT = "https://prothos-oauth-canary.example/cb"

REDIRECT_BYPASSES: list[str] = [
    EVIL_REDIRECT,
    "{orig}.prothos-oauth-canary.example",
    "{orig}@prothos-oauth-canary.example",
    "{orig}/../prothos-oauth-canary.example",
    "{orig}%2f%2e%2e%2fprothos-oauth-canary.example",
    "https://prothos-oauth-canary.example#{orig}",
    "https://prothos-oauth-canary.example/?x={orig}",
    "{orig}.evil-prothos.example",
    "{orig}%00.prothos-oauth-canary.example",
    "{orig}&redirect_uri=https://prothos-oauth-canary.example",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class OAuthFinding:
    url:        str
    issue:      str
    detail:     str
    status:     int          = 0
    evidence:   str          = ""
    severity:   str          = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class OAuthReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    params_seen: list[str]           = field(default_factory=list)
    findings:    list[OAuthFinding]  = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def high(self) -> list[OAuthFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _set_params(url: str, updates: dict) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for k, v in updates.items():
        if v is None:
            qs.pop(k, None)
        else:
            qs[k] = [v]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True, safe=":/?#@%.")))


def _location_host(location: str) -> str:
    return (urlparse(location if "://" in location else f"http:{location}").hostname or "").lower()


def _analyze_static(url: str, report: OAuthReport):
    qs = parse_qs(urlparse(url).query)
    report.params_seen = sorted(qs.keys())

    response_type = (qs.get("response_type", [""])[0]).lower()

    if "state" not in qs or not qs.get("state", [""])[0]:
        f = OAuthFinding(url=url, issue="Missing state", severity="medium",
                         detail="No state parameter in authorize request — CSRF on the OAuth flow possible",
                         evidence="state param absent/empty")
        report.findings.append(f)
        _print_finding(f)
    else:
        state = qs["state"][0]
        if len(state) < 8 or state.isdigit():
            f = OAuthFinding(url=url, issue="Weak state", severity="low",
                             detail=f"state looks weak/guessable: '{state[:16]}'",
                             evidence=f"len={len(state)}")
            report.findings.append(f)
            _print_finding(f)

    if "token" in response_type:
        f = OAuthFinding(url=url, issue="Implicit flow", severity="high",
                         detail="response_type=token exposes access token in URL fragment (implicit flow)",
                         evidence=f"response_type={response_type}")
        report.findings.append(f)
        _print_finding(f)

    if "code_challenge" not in qs and "code" in response_type:
        f = OAuthFinding(url=url, issue="No PKCE", severity="medium",
                         detail="Authorization code flow without code_challenge (PKCE) — code interception risk",
                         evidence="code_challenge absent")
        report.findings.append(f)
        _print_finding(f)


async def _test_redirect_bypass(client, url, sem, report):
    qs = parse_qs(urlparse(url).query)
    orig = qs.get("redirect_uri", [""])[0]
    if not orig:
        return

    async with sem:
        for tpl in REDIRECT_BYPASSES:
            candidate = tpl.format(orig=orig)
            test_url = _set_params(url, {"redirect_uri": candidate})
            try:
                r = await client.get(test_url, timeout=12)
            except Exception:
                continue
            location = {k.lower(): v for k, v in r.headers.items()}.get("location", "")
            host = _location_host(location)
            if "prothos-oauth-canary.example" in host or "evil-prothos.example" in host:
                f = OAuthFinding(url=test_url, issue="redirect_uri bypass", severity="critical",
                                 detail=f"Server redirected to attacker host: {candidate}",
                                 status=r.status_code, evidence=f"Location host: {host}")
                report.findings.append(f)
                _print_finding(f)
                return
            if location and ("code=" in location or "access_token=" in location):
                if "prothos-oauth-canary.example" in location:
                    f = OAuthFinding(url=test_url, issue="redirect_uri bypass (token)", severity="critical",
                                     detail="Token/code delivered to attacker redirect_uri",
                                     status=r.status_code, evidence=location[:90])
                    report.findings.append(f)
                    _print_finding(f)
                    return


async def _test_state_drop(client, url, sem, report):
    qs = parse_qs(urlparse(url).query)
    if "state" not in qs:
        return
    async with sem:
        test_url = _set_params(url, {"state": None})
        try:
            r = await client.get(test_url, timeout=12)
        except Exception:
            return
        location = {k.lower(): v for k, v in r.headers.items()}.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and "error" not in location.lower():
            f = OAuthFinding(url=test_url, issue="state not enforced", severity="medium",
                             detail="Flow proceeds without state parameter — server does not require it",
                             status=r.status_code, evidence="redirect without error on missing state")
            report.findings.append(f)
            _print_finding(f)


async def _test_referer_leak(client, url, sem, report):
    async with sem:
        try:
            r = await client.get(url, timeout=12)
        except Exception:
            return
        location = {k.lower(): v for k, v in r.headers.items()}.get("location", "")
        if ("code=" in location or "access_token=" in location):
            f = OAuthFinding(url=url, issue="Token in URL", severity="medium",
                             detail="Authorization code/token returned in URL — leaks via Referer to third parties",
                             status=r.status_code, evidence=location[:90])
            report.findings.append(f)
            _print_finding(f)


def _print_finding(f: OAuthFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.issue}[/bold white] → "
        f"[yellow]{f.detail[:60]}[/yellow]"
    )


def _display(report: OAuthReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]params:[/dim] {len(report.params_seen)}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high+:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]OAuth Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No OAuth issues found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Issue",     style="bold white", width=24)
    table.add_column("Detail",    style="yellow", min_width=40)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.issue, f.detail,
        )

    console.print(table)
    console.print()


async def _oauth_async(target, concurrency, proxy) -> OAuthReport:
    report = OAuthReport(target=target)
    sem = asyncio.Semaphore(concurrency)

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
            task_id = progress.add_task("Scanning OAuth...", total=None)

            _analyze_static(target, report)
            await _test_redirect_bypass(client, target, sem, report)
            await _test_state_drop(client, target, sem, report)
            await _test_referer_leak(client, target, sem, report)
            progress.update(task_id, completed=1, total=1)

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_oauth_scan(
    target:        str,
    concurrency:   int            = 8,
    proxy:         Optional[str]  = None,
    save_json:     Optional[str]  = None,
) -> OAuthReport:

    console.print(f"\n[bold red][*][/bold red] OAuth Scan → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Checks: redirect_uri, state, PKCE, implicit flow, token leakage[/dim]")

    report = asyncio.run(_oauth_async(
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
