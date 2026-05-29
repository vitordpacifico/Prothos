import asyncio
import json
import re
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

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS Access Key",      r"AKIA[0-9A-Z]{16}", "high"),
    ("AWS Secret Key",      r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "critical"),
    ("AWS Session Token",   r"(?i)aws_session_token['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})", "high"),
    ("Google API Key",      r"AIza[0-9A-Za-z\-_]{35}", "high"),
    ("Google OAuth",        r"ya29\.[0-9A-Za-z\-_]+", "high"),
    ("GitHub Token",        r"gh[pousr]_[0-9A-Za-z]{36}", "critical"),
    ("GitHub PAT (fine)",   r"github_pat_[0-9A-Za-z_]{82}", "critical"),
    ("Slack Token",         r"xox[baprs]-[0-9A-Za-z\-]{10,48}", "high"),
    ("Slack Webhook",       r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+", "medium"),
    ("Stripe Live Key",     r"sk_live_[0-9a-zA-Z]{24,}", "critical"),
    ("Stripe Publishable",  r"pk_live_[0-9a-zA-Z]{24,}", "low"),
    ("Twilio SID",          r"AC[a-z0-9]{32}", "medium"),
    ("SendGrid Key",        r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", "high"),
    ("Mailgun Key",         r"key-[0-9a-zA-Z]{32}", "high"),
    ("Heroku API Key",      r"(?i)heroku[a-z0-9_ .\-,]{0,25}['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]", "high"),
    ("Private Key Block",   r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----", "critical"),
    ("JWT",                 r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "medium"),
    ("Generic API Key",     r"(?i)(?:api[_-]?key|apikey|secret|token)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{16,64})['\"]", "medium"),
    ("Password Assignment", r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"\s]{6,40})['\"]", "high"),
    ("Basic Auth in URL",   r"https?://[^:@/\s]+:[^@/\s]+@", "high"),
    ("DB Connection String",r"(?i)(?:mongodb|postgres(?:ql)?|mysql|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", "critical"),
    ("Firebase URL",        r"https://[a-z0-9\-]+\.firebaseio\.com", "low"),
    ("Authorization Bearer",r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9\-._~+/]{20,}", "medium"),
]

CONFIG_PATHS: list[str] = [
    "/.env", "/.env.local", "/.env.production", "/config.json", "/config.js",
    "/app.config.js", "/settings.py", "/wp-config.php", "/config.php",
    "/.git/config", "/credentials", "/api/config", "/actuator/env",
    "/.aws/credentials", "/secrets.json", "/firebase.json", "/manifest.json",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class CredentialFinding:
    kind:       str
    source:     str
    match:      str
    severity:   str          = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class CredentialReport:
    target:      str
    started_at:  str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None
    sources:     int                      = 0
    findings:    list[CredentialFinding]  = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    @property
    def critical(self) -> list[CredentialFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> list[CredentialFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 12:
        return value[:4] + "****"
    return value[:6] + "****" + value[-4:]


def _scan(text: str, source: str, seen: set) -> list[CredentialFinding]:
    findings = []
    for kind, pattern, severity in SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            raw = m.group(0)
            key = (kind, raw[:40], source)
            if key in seen:
                continue
            seen.add(key)
            f = CredentialFinding(kind=kind, source=source, match=_redact(raw), severity=severity)
            findings.append(f)
            _print_finding(f)
    return findings


async def _fetch(client, url, sem) -> tuple[str, str]:
    async with sem:
        try:
            r = await client.get(url, timeout=12)
            return url, r.text
        except Exception:
            return url, ""


def _print_finding(f: CredentialFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.kind}[/bold white] → "
        f"[yellow]{f.match}[/yellow]  [dim]{f.source}[/dim]"
    )


def _display(report: CredentialReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]sources:[/dim] {report.sources}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]",
        title="[bold red]Credential Finder — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No leaked credentials found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Kind",      style="cyan", width=22)
    table.add_column("Match",     style="yellow", width=24)
    table.add_column("Source",    style="dim", min_width=25)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.kind, f.match, f.source[:45])

    console.print(table)
    console.print()


async def _cred_async(target, concurrency, proxy) -> CredentialReport:
    report = CredentialReport(target=target)
    seen: set = set()
    sem = asyncio.Semaphore(concurrency)
    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
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
            progress.add_task("Scanning for credentials...", total=None)

            try:
                main = await client.get(target, timeout=12)
                report.sources += 1
                report.findings.extend(_scan(main.text, target, seen))
                js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', main.text, re.IGNORECASE)
            except Exception as e:
                report.errors.append(f"main fetch: {str(e)[:100]}")
                js_urls = []

            js_full = []
            for src in js_urls[:30]:
                js_full.append(src if "://" in src else urljoin(root + "/", src))

            urls = js_full + [urljoin(root, p) for p in CONFIG_PATHS]
            tasks = [_fetch(client, u, sem) for u in urls]
            for coro in asyncio.as_completed(tasks):
                url, text = await coro
                if text:
                    report.sources += 1
                    report.findings.extend(_scan(text, url, seen))

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_credential_finder(
    target:      str,
    concurrency: int            = 12,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> CredentialReport:

    console.print(f"\n[bold red][*][/bold red] Credential Finder → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Patterns: {len(SECRET_PATTERNS)}  Config paths: {len(CONFIG_PATHS)}[/dim]")

    report = asyncio.run(_cred_async(target=target, concurrency=concurrency, proxy=proxy))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
