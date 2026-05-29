import asyncio
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

SESSION_COOKIE_HINTS = ("sess", "sid", "token", "auth", "jwt", "phpsessid", "jsessionid", "asp.net")

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class SessionFinding:
    cookie:     str
    issue:      str
    detail:     str
    severity:   str          = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SessionHijackReport:
    target:      str
    started_at:  str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None
    cookies_seen: list[str]               = field(default_factory=list)
    findings:    list[SessionFinding]     = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    @property
    def high(self) -> list[SessionFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_session_cookie(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in SESSION_COOKIE_HINTS)


def _looks_predictable(values: list[str]) -> Optional[str]:
    numeric = [v for v in values if v.isdigit()]
    if len(numeric) >= 2:
        ints = sorted(int(v) for v in numeric)
        diffs = {ints[i + 1] - ints[i] for i in range(len(ints) - 1)}
        if diffs and max(diffs) <= 5:
            return "values are sequential/incremental"
    for v in values:
        if re.fullmatch(r"\d{10}", v) or re.fullmatch(r"\d{13}", v):
            return "value resembles a unix timestamp"
    return None


def _analyze_cookie(name, value, raw, report):
    flags = raw.lower()
    if not _is_session_cookie(name):
        return
    report.cookies_seen.append(name)

    missing = []
    if "httponly" not in flags:
        missing.append("HttpOnly")
    if "secure" not in flags:
        missing.append("Secure")
    if "samesite" not in flags:
        missing.append("SameSite")
    if missing:
        sev = "high" if "HttpOnly" in missing or "Secure" in missing else "medium"
        _add(report, name, "Missing cookie flags", f"missing: {', '.join(missing)}", sev)

    ent = _entropy(value)
    if len(value) < 16:
        _add(report, name, "Short session token", f"length {len(value)} — brute-forceable", "high")
    if ent < 3.0 and len(value) >= 8:
        _add(report, name, "Low entropy token", f"Shannon entropy {ent:.2f} bits/char", "high")


def _add(report, cookie, issue, detail, severity):
    f = SessionFinding(cookie=cookie, issue=issue, detail=detail, severity=severity)
    report.findings.append(f)
    _print_finding(f)


def _print_finding(f: SessionFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.cookie}[/bold white] → "
        f"[yellow]{f.issue}[/yellow] [dim]{f.detail}[/dim]"
    )


def _display(report: SessionHijackReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]session cookies:[/dim] {len(set(report.cookies_seen))}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Session Security — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No session weaknesses found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Cookie",    style="bold white", width=18)
    table.add_column("Issue",     style="cyan", width=24)
    table.add_column("Detail",    style="yellow", min_width=25)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.cookie, f.issue, f.detail[:40])

    console.print(table)
    console.print()


async def _session_async(target, samples, concurrency, proxy) -> SessionHijackReport:
    report = SessionHijackReport(target=target)
    token_values: dict[str, list[str]] = {}

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
            progress.add_task("Analyzing session...", total=None)

            for i in range(max(1, samples)):
                try:
                    r = await client.get(target, timeout=12)
                except Exception as e:
                    report.errors.append(str(e)[:120])
                    continue
                raws = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else \
                    ([r.headers["set-cookie"]] if "set-cookie" in r.headers else [])
                for raw in raws:
                    first = raw.split(";")[0]
                    if "=" not in first:
                        continue
                    name, value = first.split("=", 1)
                    if i == 0:
                        _analyze_cookie(name.strip(), value.strip(), raw, report)
                    token_values.setdefault(name.strip(), []).append(value.strip())
                client.cookies.clear()

            for name, values in token_values.items():
                if not _is_session_cookie(name):
                    continue
                pred = _looks_predictable(values)
                if pred:
                    _add(report, name, "Predictable session token", pred, "critical")

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_session_hijack(
    target:      str,
    samples:     int            = 5,
    concurrency: int            = 1,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> SessionHijackReport:

    console.print(f"\n[bold red][*][/bold red] Session Security → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Sampling {samples} responses for cookie flags, entropy, predictability[/dim]")

    report = asyncio.run(_session_async(target, samples, concurrency, proxy))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
