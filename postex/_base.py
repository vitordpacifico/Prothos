"""Shared scaffolding for post-exploitation modules.

Post-ex requires a stronger consent gate than scanning: RoE.allow_postex (or
lab mode). Modules compose with an `exec_fn` — a callable that runs a command
on the compromised host and returns stdout — which can be wired from
cmdi_exploit, a reverse shell, or the c2 beacon. Without an exec_fn, modules
emit the checklist/commands instead of running them.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.roe import get_roe
from core.scope import get_guard
from core import audit

console = Console()

# exec_fn signature: (command: str) -> str (stdout) | None
ExecFn = Callable[[str], Optional[str]]


@dataclass
class PostexItem:
    check:    str
    result:   str
    severity: str = "info"     # info/low/medium/high/critical
    finding:  bool = False     # True if this represents an exploitable weakness

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class PostexReport:
    module:      str
    target:      str
    started_at:  str               = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]     = None
    mode:        str               = "checklist"   # "live" if exec_fn ran commands
    items:       list[PostexItem]  = field(default_factory=list)
    loot:        list[str]         = field(default_factory=list)
    refused:     Optional[str]     = None
    errors:      list[str]         = field(default_factory=list)

    def add(self, check: str, result: str, severity: str = "info", finding: bool = False):
        item = PostexItem(check=check, result=result, severity=severity, finding=finding)
        self.items.append(item)
        tag = "[red][!][/red]" if finding else "[dim][*][/dim]"
        console.print(f"  {tag} [white]{check}[/white] [dim]{result[:80]}[/dim]")
        return item

    def add_loot(self, item: str):
        self.loot.append(item)
        console.print(f"  [bold green][LOOT][/bold green] [yellow]{item[:100]}[/yellow]")

    @property
    def findings(self) -> list[PostexItem]:
        return [i for i in self.items if i.finding]

    def finish(self):
        self.finished_at = datetime.now(timezone.utc).isoformat()
        return self

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["items"] = [i.to_dict() for i in self.items]
        # expose as findings for the session ingester
        d["findings"] = [
            {"title": i.check, "description": i.result, "severity": i.severity}
            for i in self.items if i.finding
        ]
        return d


def preflight(module: str, target: str, allow_postex: bool, lab: bool) -> Optional[PostexReport]:
    report = PostexReport(module=module, target=target)
    audit.audit("postex_attempt", module=module, target=target, severity="high")

    if not (lab or get_guard().in_scope(target)):
        msg = "target outside authorized scope"
        report.refused = msg
        audit.audit("postex_refused", module=module, target=target, result=msg)
        _refuse(module, msg)
        return report.finish()

    if not (lab or allow_postex):
        ok, reason = get_roe().can_postex()
        if not ok:
            msg = f"post-ex consent missing — {reason}"
            report.refused = msg
            audit.audit("postex_refused", module=module, target=target, result=msg)
            _refuse(module, msg)
            return report.finish()

    audit.audit("postex_authorized", module=module, target=target, severity="high")
    return None


def _refuse(module: str, reason: str):
    console.print(Panel(
        f"[bold red]REFUSED[/bold red] — {reason}\n"
        f"[dim]Set RoE allow_postex, or use lab mode for owned/CTF targets.[/dim]",
        title=f"[bold red]postex/{module}[/bold red]", border_style="red", expand=False,
    ))


def display(report: PostexReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]mode:[/dim] {report.mode}  "
        f"[dim]checks:[/dim] {len(report.items)}  "
        f"[dim]weaknesses:[/dim] [red]{len(report.findings)}[/red]  "
        f"[dim]loot:[/dim] [yellow]{len(report.loot)}[/yellow]",
        title=f"[bold red]postex/{report.module}[/bold red]", border_style="red", expand=False,
    ))
    if report.findings:
        table = Table(show_header=True, header_style="bold red", border_style="dim")
        table.add_column("Sev", width=9)
        table.add_column("Check", style="white", width=24)
        table.add_column("Result", style="yellow", min_width=30)
        for i in report.findings:
            table.add_row(i.severity, i.check, i.result[:50])
        console.print(table)
    console.print()


def save(report: PostexReport, save_json: Optional[str]):
    if not save_json:
        return
    try:
        with open(save_json, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        console.print(f"[dim][+] Saved to {save_json}[/dim]")
    except OSError as e:
        console.print(f"[red][!] Failed to save: {e}[/red]")


def header(module: str, target: str, mode: str):
    console.print(f"\n[bold red][*][/bold red] postex/{module} → "
                  f"[bold white]{target}[/bold white] [dim]({mode})[/dim]")
