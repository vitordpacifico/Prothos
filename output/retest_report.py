"""Markdown retest report — renders a RetestResult into a deliverable."""

from datetime import datetime, timezone
from typing import Optional
from rich.console import Console

from core.retest import RetestResult

console = Console()


def _section(title: str, items: list[dict]) -> str:
    if not items:
        return f"### {title} (0)\n\n_None._\n"
    lines = [f"### {title} ({len(items)})\n"]
    lines.append("| Severity | Finding | URL | Param |")
    lines.append("|----------|---------|-----|-------|")
    for f in items:
        lines.append(
            f"| {f.get('severity','-')} | {str(f.get('title','-'))[:80]} "
            f"| {str(f.get('url') or '-')[:60]} | {f.get('param') or '-'} |"
        )
    return "\n".join(lines) + "\n"


def run_retest_report(
    result:    RetestResult,
    path:      str,
    target:    str = "",
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = [
        f"# Prothos — Retest Report",
        f"\n**Target:** {target or 'n/a'}  ",
        f"**Generated:** {ts}\n",
        "## Summary\n",
        f"- ✅ Resolved: **{len(result.resolved)}**",
        f"- ⚠️ Persistent: **{len(result.persistent)}**",
        f"- 🔴 New: **{len(result.new)}**\n",
        _section("⚠️ Persistent (still vulnerable)", result.persistent),
        _section("🔴 New (regressions / newly found)", result.new),
        _section("✅ Resolved (remediation confirmed)", result.resolved),
    ]
    content = "\n".join(md)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"[green][+] Retest report written to {path}[/green]")
    except OSError as e:
        console.print(f"[red][!] Failed to write report: {e}[/red]")
    return content
