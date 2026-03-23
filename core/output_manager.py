import json
import gzip
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.session import Session, Finding

console = Console()

class OutputManager:

    SEVERITY_COLOR = {
        "critical": "bold red",
        "high":     "red",
        "medium":   "yellow",
        "low":      "dim",
        "info":     "cyan",
    }

    def __init__(
        self,
        session:    Session,
        output_dir: str | Path     = "output",
        json:       bool           = True,
        html:       bool           = True,
        compress:   bool           = False,
        silent:     bool           = False,
    ):
        self.session    = session
        self.output_dir = Path(output_dir)
        self.do_json    = json
        self.do_html    = html
        self.compress   = compress
        self.silent     = silent

        self.output_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._base = self.output_dir / f"session_{ts}"

    def print_finding(self, finding: Finding):
        if self.silent:
            return

        color = self.SEVERITY_COLOR.get(finding.severity, "white")

        console.print(
            f"  [{color}]{finding.severity.upper()}[/{color}] "
            f"[bold white]{finding.title}[/bold white] "
            f"[dim]({finding.module})[/dim]"
        )

        if finding.url:
            console.print(f"     [dim]url:[/dim] [cyan]{finding.url}[/cyan]")
        if finding.param:
            console.print(f"     [dim]param:[/dim] {finding.param}")
        if finding.payload:
            console.print(f"     [dim]payload:[/dim] [yellow]{finding.payload[:80]}[/yellow]")
        if finding.evidence:
            console.print(f"     [dim]evidence:[/dim] [italic]{finding.evidence[:100]}[/italic]")

    def print_module_start(self, module: str, target: str = ""):
        if self.silent:
            return
        t = f" → [bold white]{target}[/bold white]" if target else ""
        console.print(f"\n[bold red][*][/bold red] {module}{t}")

    def print_module_done(self, module: str, count: int = 0):
        if self.silent:
            return
        console.print(
            f"[dim]    [+] {module} done"
            f"{f' — {count} findings' if count else ''}[/dim]"
        )

    def print_module_error(self, module: str, error: str):
        if self.silent:
            return
        console.print(f"[red]    [!] {module} failed: {error}[/red]")

    def print_info(self, msg: str):
        if self.silent:
            return
        console.print(f"[dim]    {msg}[/dim]")

    def print_summary(self):
        if self.silent:
            return

        s       = self.session
        summary = s.summary()

        console.print()
        console.print(Panel(
            f"[bold white]{s.target}[/bold white]  "
            f"[dim]session:[/dim] {s.id}  "
            f"[dim]duration:[/dim] {summary['duration_s']}s  "
            f"[dim]modules:[/dim] {len(s.modules_run)}",
            title="[bold red]Prothos — Session Summary[/bold red]",
            border_style="red",
        ))

        table = Table(
            show_header=True,
            header_style="bold red",
            border_style="dim",
        )
        table.add_column("Severity", width=10)
        table.add_column("Count",    width=8)
        table.add_column("Findings", style="dim")

        severities = [
            ("critical", "bold red"),
            ("high",     "red"),
            ("medium",   "yellow"),
            ("low",      "dim"),
            ("info",     "cyan"),
        ]

        for sev, color in severities:
            findings = s.by_severity(sev)
            if not findings:
                continue
            titles = ", ".join(set(f.title for f in findings[:5]))
            if len(findings) > 5:
                titles += f" +{len(findings)-5} more"
            table.add_row(
                f"[{color}]{sev.upper()}[/{color}]",
                f"[{color}]{len(findings)}[/{color}]",
                titles,
            )

        console.print(table)

        if s.critical:
            console.print(f"\n[bold red][!] CRITICAL FINDINGS: {len(s.critical)}[/bold red]")
            for f in s.critical:
                console.print(
                    f"    [red]→[/red] [bold]{f.title}[/bold] "
                    f"[dim]({f.module})[/dim]"
                    + (f" [cyan]{f.url}[/cyan]" if f.url else "")
                )

        if s.modules_failed:
            console.print(f"\n[yellow][!] Failed modules: {', '.join(s.modules_failed)}[/yellow]")

        console.print()

    def _json_path(self) -> Path:
        p = Path(str(self._base) + ".json")
        return Path(str(self._base) + ".json.gz") if self.compress else p

    def _html_path(self) -> Path:
        return Path(str(self._base) + ".html")

    def export_json(self) -> Optional[Path]:
        try:
            from output.json_exporter import export_json
            path = export_json(
                self.session.to_dict(),
                self._json_path(),
                compress=self.compress,
            )
            return path
        except Exception as e:
            console.print(f"[red][!] JSON export failed: {e}[/red]")
            return None

    def export_html(self) -> Optional[Path]:
        try:
            from output.html_exporter import export_html
            data = self.session.to_dict()
            data["target"] = self.session.target
            path = export_html(data, self._html_path())
            return path
        except Exception as e:
            console.print(f"[red][!] HTML export failed: {e}[/red]")
            return None

    def finalize(self):
        self.session.finish()
        self.print_summary()

        exports = []

        if self.do_json:
            path = self.export_json()
            if path:
                exports.append(str(path))

        if self.do_html:
            path = self.export_html()
            if path:
                exports.append(str(path))

        if exports and not self.silent:
            console.print("[dim]Reports:[/dim]")
            for p in exports:
                console.print(f"  [cyan]→ {p}[/cyan]")
            console.print()


def create_output_manager(
    session:    Session,
    output_dir: str | Path = "output",
    **kwargs,
) -> OutputManager:
    return OutputManager(session=session, output_dir=output_dir, **kwargs)