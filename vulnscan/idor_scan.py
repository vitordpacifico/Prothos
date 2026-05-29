import asyncio
import json
import re
import uuid as uuidlib
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

TEST_IDS: list[str] = ["0", "1", "2", "3", "999", "1000", "-1", "9999999"]

UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)

DENY_MARKERS: list[str] = [
    "access denied", "forbidden", "unauthorized", "not authorized",
    "permission denied", "you do not have", "no permission", "not allowed",
    "404 not found", "does not exist", "no such", "invalid id", "error",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class IDORFinding:
    url:         str
    location:    str
    original:    str
    tested:      str
    status:      int          = 0
    self_status: int          = 0
    evidence:    str          = ""
    severity:    str          = "high"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class IDORReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    id_locations: list[str]          = field(default_factory=list)
    findings:    list[IDORFinding]   = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def high(self) -> list[IDORFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _candidate_values(original: str) -> list[str]:
    values = []
    if original.lstrip("-").isdigit():
        n = int(original)
        for delta in (1, -1, 2, -2):
            values.append(str(n + delta))
        values.extend(TEST_IDS)
    elif UUID_RE.fullmatch(original):
        values.append(str(uuidlib.uuid4()))
        values.append("00000000-0000-0000-0000-000000000000")
        values.append("11111111-1111-1111-1111-111111111111")
    seen, out = set(), []
    for v in values:
        if v != original and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _path_id_variants(url: str) -> list[tuple[str, str, str]]:
    parsed = urlparse(url)
    segments = parsed.path.split("/")
    variants = []
    for i, seg in enumerate(segments):
        if seg.lstrip("-").isdigit() or UUID_RE.fullmatch(seg):
            for val in _candidate_values(seg):
                new_segs = segments.copy()
                new_segs[i] = val
                new_path = "/".join(new_segs)
                new_url = urlunparse(parsed._replace(path=new_path))
                variants.append((f"path[{i}]", seg, new_url))
    return variants


def _query_id_variants(url: str) -> list[tuple[str, str, str]]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    variants = []
    for key, vals in qs.items():
        original = vals[0] if vals else ""
        if original.lstrip("-").isdigit() or UUID_RE.fullmatch(original):
            for val in _candidate_values(original):
                new_qs = {k: v[:] for k, v in qs.items()}
                new_qs[key] = [val]
                new_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
                variants.append((f"param:{key}", original, new_url))
    return variants


def _looks_denied(body: str, status: int) -> bool:
    if status in (401, 403, 404):
        return True
    low = body[:5000].lower()
    return any(m in low for m in DENY_MARKERS)


def _similarity(a: str, b: str) -> float:
    la, lb = len(a), len(b)
    if max(la, lb) == 0:
        return 1.0
    return 1.0 - abs(la - lb) / max(la, lb)


async def _test_variant(client, base_url, location, original, variant_url,
                        self_status, self_body, sem) -> Optional[IDORFinding]:
    async with sem:
        try:
            r = await client.get(variant_url, timeout=12)
        except Exception:
            return None

        if r.status_code not in (200, 201, 202):
            return None
        if _looks_denied(r.text, r.status_code):
            return None

        sim = _similarity(self_body, r.text[:20000])
        if self_status in (200, 201, 202) and 0.4 < sim < 0.99:
            f = IDORFinding(
                url=variant_url, location=location, original=original,
                tested=variant_url.split(original)[-1][:20] if original in variant_url else "?",
                status=r.status_code, self_status=self_status,
                evidence=f"200 OK, structure similar ({sim:.2f}) but content differs — possible other user's object",
                severity="high",
            )
            _print_finding(f)
            return f
        if self_status in (401, 403, 404) and r.status_code in (200, 201, 202):
            f = IDORFinding(
                url=variant_url, location=location, original=original,
                tested=variant_url, status=r.status_code, self_status=self_status,
                evidence=f"object accessible ({r.status_code}) where baseline was {self_status}",
                severity="high",
            )
            _print_finding(f)
            return f
    return None


def _print_finding(f: IDORFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.location}[/bold white] "
        f"[dim]{f.original} →[/dim] "
        f"[yellow]{f.evidence[:55]}[/yellow]"
    )


def _display(report: IDORReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]id locations:[/dim] {len(report.id_locations)}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]IDOR Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No IDOR found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Location",  style="bold white", width=16)
    table.add_column("Original",  style="cyan", width=14)
    table.add_column("Status",    style="dim", width=8)
    table.add_column("Evidence",  style="yellow", min_width=30)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.location, f.original[:14],
            f"{f.self_status}->{f.status}", f.evidence[:45],
        )

    console.print(table)
    console.print()


async def _idor_async(target, token, scheme, cookies, concurrency, proxy) -> IDORReport:
    report = IDORReport(target=target)
    variants = _path_id_variants(target) + _query_id_variants(target)
    report.id_locations = sorted(set(v[0] for v in variants))
    sem = asyncio.Semaphore(concurrency)

    headers = {"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"}
    if token:
        headers["Authorization"] = f"{scheme} {token}"

    cookie_jar = {}
    if cookies:
        for pair in cookies.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookie_jar[k.strip()] = v.strip()

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        proxy=proxy,
        headers=headers,
        cookies=cookie_jar,
    ) as client:

        try:
            self_resp = await client.get(target, timeout=12)
            self_status, self_body = self_resp.status_code, self_resp.text[:20000]
        except Exception as e:
            report.errors.append(f"baseline fetch failed: {e}")
            self_status, self_body = 0, ""

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=35, style="red", complete_style="green"),
            TextColumn("[green]{task.completed}[/green]/[white]{task.total}[/white]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Scanning IDOR...", total=len(variants) or 1)
            tasks = [
                _test_variant(client, target, loc, orig, vurl, self_status, self_body, sem)
                for loc, orig, vurl in variants
            ]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    report.findings.append(result)
                progress.advance(task_id, 1)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_idor_scan(
    target:        str,
    token:         Optional[str]  = None,
    auth_scheme:   str            = "Bearer",
    cookies:       Optional[str]  = None,
    concurrency:   int            = 10,
    proxy:         Optional[str]  = None,
    save_json:     Optional[str]  = None,
) -> IDORReport:

    console.print(f"\n[bold red][*][/bold red] IDOR Scan → [bold white]{target}[/bold white]")
    locs = sorted(set(v[0] for v in (_path_id_variants(target) + _query_id_variants(target))))
    console.print(f"[dim]    ID locations: {', '.join(locs) or 'none detected'}  "
                  f"auth: {'token' if token else ('cookie' if cookies else 'none')}[/dim]")

    report = asyncio.run(_idor_async(
        target=target,
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
