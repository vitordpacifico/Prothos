"""Post-engagement artifact tracking & cleanup report.

Reads the audit trail for everything Prothos touched that should be reverted
(planted files, opened sessions, anything recorded via audit.audit_artifact)
and produces a cleanup checklist so the engagement leaves the target clean.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core import audit

console = Console()


@dataclass
class CleanupReport:
    session:     str
    generated:   str               = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    artifacts:   list[dict]        = field(default_factory=list)

    @property
    def pending(self) -> list[dict]:
        return [a for a in self.artifacts if not a.get("cleaned")]

    def to_dict(self) -> dict:
        return {
            "session":   self.session,
            "generated": self.generated,
            "total":     len(self.artifacts),
            "pending":   len(self.pending),
            "artifacts": self.artifacts,
        }


def build_cleanup_report(audit_path: Optional[str] = None, session: str = "session") -> CleanupReport:
    report = CleanupReport(session=session)
    for ev in audit.artifacts(audit_path):
        report.artifacts.append({
            "kind":     ev.get("kind", "?"),
            "location": ev.get("location", ""),
            "module":   ev.get("module", ""),
            "target":   ev.get("target", ""),
            "cleanup":  ev.get("cleanup", ""),
            "ts":       ev.get("ts", ""),
            "cleaned":  False,
        })
    return report


def display(report: CleanupReport):
    console.print()
    console.print(Panel(
        f"[bold white]session {report.session}[/bold white]  "
        f"[dim]artifacts:[/dim] {len(report.artifacts)}  "
        f"[dim]pending cleanup:[/dim] [red]{len(report.pending)}[/red]",
        title="[bold red]Post-Engagement — Cleanup Report[/bold red]",
        border_style="red", expand=False,
    ))
    if not report.artifacts:
        console.print("[green]    Nothing planted — target is clean.[/green]\n")
        return
    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Kind", style="cyan", width=14)
    table.add_column("Location", style="white", min_width=24)
    table.add_column("Cleanup command / action", style="yellow", min_width=30)
    for a in report.artifacts:
        table.add_row(a["kind"], a["location"][:40], a["cleanup"][:50] or "(manual)")
    console.print(table)
    console.print()


def run_cleanup_report(
    audit_path: Optional[str] = None,
    session:    str           = "session",
    save_json:  Optional[str] = None,
) -> CleanupReport:
    """Generate the cleanup checklist from the audit trail."""
    report = build_cleanup_report(audit_path, session)
    display(report)
    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")
    return report
