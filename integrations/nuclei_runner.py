import asyncio
import json
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class NucleiFinding:
    template_id: str
    name:        str
    severity:    str
    matched_at:  str
    tags:        list[str]    = field(default_factory=list)
    description: str          = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class NucleiReport:
    targets:     list[str]
    started_at:  str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None
    templates:   Optional[str]            = None
    total:       int                      = 0
    findings:    list[NucleiFinding]      = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    @property
    def critical(self) -> list[NucleiFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> list[NucleiFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _parse_line(line: str) -> Optional[NucleiFinding]:
    try:
        obj = json.loads(line)
    except Exception:
        return None
    info = obj.get("info", {})
    sev = (info.get("severity") or "info").lower()
    if sev not in VALID_SEVERITIES:
        sev = "info"
    return NucleiFinding(
        template_id=obj.get("template-id", obj.get("templateID", "")),
        name=info.get("name", ""),
        severity=sev,
        matched_at=obj.get("matched-at", obj.get("host", "")),
        tags=info.get("tags", []) if isinstance(info.get("tags"), list) else [],
        description=(info.get("description") or "")[:300],
    )


def _print_finding(f: NucleiFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.template_id}[/bold white] → "
        f"[yellow]{f.matched_at}[/yellow]"
    )


def _display(report: NucleiReport):
    console.print()
    console.print(Panel(
        f"[dim]targets:[/dim] {len(report.targets)}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Nuclei Runner — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No nuclei findings.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Template",  style="bold white", width=30)
    table.add_column("Matched",   style="yellow", min_width=30)

    for f in sorted(report.findings, key=lambda x: list(VALID_SEVERITIES).index(x.severity) if x.severity in VALID_SEVERITIES else 99):
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.template_id, f.matched_at)

    console.print(table)
    console.print()


async def _nuclei_async(targets, templates, severity, extra_args) -> NucleiReport:
    report = NucleiReport(targets=targets, templates=templates)

    binary = shutil.which("nuclei")
    if not binary:
        report.errors.append("nuclei binary not found in PATH")
        console.print("[red][!] nuclei not installed — see https://github.com/projectdiscovery/nuclei[/red]")
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report

    tmp = Path(tempfile.gettempdir()) / f"prothos_nuclei_{datetime.now().strftime('%H%M%S')}.txt"
    tmp.write_text("\n".join(targets), encoding="utf-8")

    args = [binary, "-l", str(tmp), "-jsonl", "-silent", "-no-color"]
    if templates:
        args += ["-t", templates]
    if severity:
        args += ["-severity", severity]
    if extra_args:
        args += extra_args

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[bold white]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Running nuclei...", total=None)
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout is not None
            async for raw in proc.stdout:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                report.total += 1
                f = _parse_line(line)
                if f:
                    report.findings.append(f)
                    _print_finding(f)
            stderr = await proc.stderr.read() if proc.stderr else b""
            await proc.wait()
            if proc.returncode not in (0, None) and not report.findings:
                msg = stderr.decode("utf-8", "replace")[:200]
                if msg:
                    report.errors.append(msg)
        except Exception as e:
            report.errors.append(str(e)[:200])
        finally:
            try:
                tmp.unlink()
            except Exception:
                pass

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_nuclei_runner(
    targets:     list[str],
    templates:   Optional[str]       = None,
    output:      Optional[str]       = None,
    severity:    Optional[str]       = None,
    extra_args:  Optional[list[str]] = None,
    save_json:   Optional[str]       = None,
) -> NucleiReport:

    if isinstance(targets, str):
        targets = [targets]

    console.print(f"\n[bold red][*][/bold red] Nuclei Runner → [bold white]{len(targets)} target(s)[/bold white]")
    console.print(f"[dim]    Templates: {templates or 'default'}  Severity: {severity or 'all'}[/dim]")

    report = asyncio.run(_nuclei_async(targets, templates, severity, extra_args))
    _display(report)

    out = save_json or output
    if out:
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {out}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
