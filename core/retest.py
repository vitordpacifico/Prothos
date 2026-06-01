"""Retest & session diff — phase 8 verification.

Compares a previous session against a current one and classifies each finding
as resolved (was there, now gone), persistent (still present), or new
(appeared since). This is how a retest after remediation is evidenced.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.session import Session

console = Console()


def _key(f: dict) -> tuple:
    return (
        f.get("module", ""),
        (f.get("title") or "").strip().lower(),
        f.get("url") or "",
        f.get("param") or "",
    )


def _findings_of(data) -> dict[tuple, dict]:
    if isinstance(data, Session):
        items = [fd.to_dict() for fd in data.findings]
    elif isinstance(data, dict):
        items = data.get("findings_detail") or data.get("findings") or []
    else:
        items = []
    return {_key(f): f for f in items if isinstance(f, dict)}


@dataclass
class RetestResult:
    resolved:   list[dict] = field(default_factory=list)
    persistent: list[dict] = field(default_factory=list)
    new:        list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "resolved":   len(self.resolved),
                "persistent": len(self.persistent),
                "new":        len(self.new),
            },
            "resolved":   self.resolved,
            "persistent": self.persistent,
            "new":        self.new,
        }


def diff_sessions(previous, current) -> RetestResult:
    prev = _findings_of(previous)
    curr = _findings_of(current)
    result = RetestResult()
    for k, f in prev.items():
        (result.persistent if k in curr else result.resolved).append(f)
    for k, f in curr.items():
        if k not in prev:
            result.new.append(f)
    return result


def display(result: RetestResult):
    console.print()
    console.print(Panel(
        f"[green]resolved:[/green] {len(result.resolved)}   "
        f"[yellow]persistent:[/yellow] {len(result.persistent)}   "
        f"[red]new:[/red] {len(result.new)}",
        title="[bold red]Retest — Session Diff[/bold red]",
        border_style="red", expand=False,
    ))
    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Status", width=12)
    table.add_column("Sev", width=9)
    table.add_column("Finding", style="white", min_width=30)
    table.add_column("URL", style="dim", min_width=20)
    for label, color, items in (
        ("RESOLVED", "green", result.resolved),
        ("PERSISTENT", "yellow", result.persistent),
        ("NEW", "red", result.new),
    ):
        for f in items[:30]:
            table.add_row(f"[{color}]{label}[/{color}]", f.get("severity", "-"),
                          str(f.get("title", "-"))[:40], str(f.get("url") or "-")[:30])
    console.print(table)
    console.print()


def run_retest(
    previous_path: str,
    current:       Optional[Session] = None,
    save_json:     Optional[str]     = None,
) -> RetestResult:
    """Diff a saved previous session (JSON) against the current/active one."""
    from core.session import get_session
    current = current or get_session()
    if current is None:
        console.print("[yellow][!] No current session to compare. Run modules first.[/yellow]")
        return RetestResult()

    try:
        prev = json.loads(Path(previous_path).read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[red][!] Could not load previous session: {e}[/red]")
        return RetestResult()

    result = diff_sessions(prev, current)
    display(result)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")
    return result
