import asyncio
import json
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class SqlmapFinding:
    kind:       str
    detail:     str
    severity:   str          = "info"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SqlmapReport:
    target:      str
    started_at:  str                   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]        = None
    command:     str                  = ""
    dbms:        Optional[str]        = None
    injectable:  bool                 = False
    findings:    list[SqlmapFinding]  = field(default_factory=list)
    raw_tail:    str                  = ""
    errors:      list[str]            = field(default_factory=list)

    @property
    def critical(self) -> list[SqlmapFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


PARSE_RULES: list[tuple[str, str, str, str]] = [
    (r"the back-end DBMS is (.+)",                 "dbms",       "DBMS identified", "info"),
    (r"back-end DBMS:\s*(.+)",                     "dbms",       "DBMS identified", "info"),
    (r"Parameter:\s*(.+?)\s*\(",                   "injectable", "Injectable parameter", "critical"),
    (r"is vulnerable",                             "injectable", "Parameter vulnerable", "critical"),
    (r"current user:\s*'(.+?)'",                   "info",       "Current DB user", "high"),
    (r"current database:\s*'(.+?)'",               "info",       "Current database", "medium"),
    (r"current user is DBA:\s*(True|true)",        "info",       "Current user is DBA", "high"),
    (r"available databases \[(\d+)\]",             "info",       "Databases enumerated", "medium"),
    (r"banner:\s*'(.+?)'",                         "info",       "DBMS banner", "low"),
]


def _parse_line(line: str, report: SqlmapReport, seen: set):
    for pattern, kind, label, severity in PARSE_RULES:
        m = re.search(pattern, line, re.IGNORECASE)
        if not m:
            continue
        captured = m.group(1) if m.groups() else ""
        key = (label, captured)
        if key in seen:
            continue
        seen.add(key)
        if kind == "dbms":
            report.dbms = captured.strip()
        if kind == "injectable":
            report.injectable = True
        f = SqlmapFinding(kind=label, detail=f"{label}: {captured}".strip(": "), severity=severity)
        report.findings.append(f)
        _print_finding(f)


def _print_finding(f: SqlmapFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(f"  [{color}][{f.severity.upper()}][/{color}] [yellow]{f.detail}[/yellow]")


def _display(report: SqlmapReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]dbms:[/dim] {report.dbms or '-'}  "
        f"[dim]injectable:[/dim] {'yes' if report.injectable else 'no'}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]",
        title="[bold red]sqlmap Runner — Summary[/bold red]",
        border_style="red",
    ))

    if report.findings:
        table = Table(show_header=True, header_style="bold red", border_style="dim")
        table.add_column("Severity", width=10)
        table.add_column("Finding",  style="yellow", min_width=40)
        for f in report.findings:
            color = SEVERITY_COLOR.get(f.severity, "white")
            table.add_row(f"[{color}]{f.severity}[/{color}]", f.detail)
        console.print(table)
    console.print()


async def _run_async(target, data, param, level, risk, dbms, technique, dump, proxy, extra_args) -> SqlmapReport:
    report = SqlmapReport(target=target)
    seen: set = set()

    binary = shutil.which("sqlmap") or shutil.which("sqlmap.py")
    if not binary:
        report.errors.append("sqlmap not found in PATH")
        console.print("[red][!] sqlmap not installed — https://github.com/sqlmapproject/sqlmap[/red]")
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report

    args = [binary, "-u", target, "--batch", "--disable-coloring",
            f"--level={level}", f"--risk={risk}"]
    if data:
        args += ["--data", data]
    if param:
        args += ["-p", param]
    if dbms:
        args += ["--dbms", dbms]
    if technique:
        args += [f"--technique={technique}"]
    if proxy:
        args += ["--proxy", proxy]
    args += ["--banner", "--current-user", "--current-db", "--is-dba", "--dbs"]
    if dump:
        args += ["--dump"]
    if extra_args:
        args += extra_args

    report.command = " ".join(args)
    tail: list[str] = []

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[bold white]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Running sqlmap...", total=None)
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            assert proc.stdout is not None
            async for raw in proc.stdout:
                line = raw.decode("utf-8", "replace").rstrip()
                if not line:
                    continue
                tail.append(line)
                if len(tail) > 60:
                    tail.pop(0)
                _parse_line(line, report, seen)
            await proc.wait()
        except Exception as e:
            report.errors.append(str(e)[:200])

    report.raw_tail = "\n".join(tail[-40:])
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_sqlmap_runner(
    target:      str,
    data:        Optional[str]       = None,
    param:       Optional[str]       = None,
    level:       int                 = 1,
    risk:        int                 = 1,
    dbms:        Optional[str]       = None,
    technique:   Optional[str]       = None,
    dump:        bool                = False,
    proxy:       Optional[str]       = None,
    extra_args:  Optional[list[str]] = None,
    save_json:   Optional[str]       = None,
) -> SqlmapReport:

    console.print(f"\n[bold red][*][/bold red] sqlmap Runner → [bold white]{target}[/bold white]")
    console.print(f"[dim]    level={level} risk={risk} dump={dump} "
                  f"param={param or 'auto'}[/dim]")

    report = asyncio.run(_run_async(target, data, param, level, risk, dbms, technique, dump, proxy, extra_args))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
