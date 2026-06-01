"""Threat modeling — turn raw findings into a prioritized attack plan.

Sits between assessment (phase 4) and exploitation (phase 5). It reads the
session findings, scores each one by severity x exploitability x exposure,
maps it to the native exploitation module that can act on it, and emits an
ordered plan: "attack this first, with this module".
"""

from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.session import Session, Finding

console = Console()

SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}

# finding category/tag  ->  (exploitability 0-1, native exploitation module)
EXPLOIT_MAP: dict[str, tuple[float, Optional[str]]] = {
    "sqli":         (0.95, "sqli_exploit"),
    "ssti":         (0.90, "ssti_exploit"),
    "cmdi":         (0.95, "cmdi_exploit"),
    "rce":          (0.95, "cmdi_exploit"),
    "lfi":          (0.80, "lfi_exploit"),
    "ssrf":         (0.70, "ssrf_exploit"),
    "xxe":          (0.65, "xxe_exploit"),
    "upload":       (0.85, "upload_exploit"),
    "deserialize":  (0.80, "deserialize_exploit"),
    "auth":         (0.60, None),
    "idor":         (0.55, None),
    "open_redirect":(0.30, None),
    "xss":          (0.50, None),
    "secret":       (0.75, None),
    "misconfig":    (0.40, None),
    "cve":          (0.70, None),
}

# keywords used to infer a category when the finding has no explicit tag
KEYWORD_HINTS: list[tuple[str, str]] = [
    ("sql", "sqli"), ("ssti", "ssti"), ("template", "ssti"),
    ("command inj", "cmdi"), ("rce", "rce"), ("remote code", "rce"),
    ("lfi", "lfi"), ("file inclusion", "lfi"), ("path travers", "lfi"),
    ("ssrf", "ssrf"), ("xxe", "xxe"), ("xml external", "xxe"),
    ("upload", "upload"), ("deserial", "deserialize"),
    ("idor", "idor"), ("auth", "auth"), ("redirect", "open_redirect"),
    ("xss", "xss"), ("secret", "secret"), ("api key", "secret"),
    ("cve-", "cve"), ("misconfig", "misconfig"),
]


@dataclass
class AttackNode:
    finding:        Finding
    category:       str
    score:          float
    exploitability: float
    exploit_module: Optional[str]

    @property
    def actionable(self) -> bool:
        return self.exploit_module is not None

    def to_dict(self) -> dict:
        return {
            "finding_id":     self.finding.id,
            "title":          self.finding.title,
            "severity":       self.finding.severity,
            "category":       self.category,
            "score":          round(self.score, 2),
            "exploitability": self.exploitability,
            "exploit_module": self.exploit_module,
            "url":            self.finding.url,
            "param":          self.finding.param,
        }


@dataclass
class ThreatModel:
    target: str
    nodes:  list[AttackNode] = field(default_factory=list)

    @property
    def actionable(self) -> list[AttackNode]:
        return [n for n in self.nodes if n.actionable]

    def to_dict(self) -> dict:
        return {
            "target":     self.target,
            "nodes":      [n.to_dict() for n in self.nodes],
            "actionable": len(self.actionable),
            "total":      len(self.nodes),
        }


def _infer_category(f: Finding) -> str:
    # explicit signals first
    cat = (f.extra.get("category") if isinstance(f.extra, dict) else "") or ""
    for tag in [cat, *f.tags, f.module]:
        t = str(tag).lower()
        if t in EXPLOIT_MAP:
            return t
    haystack = f"{f.title} {f.description} {f.module} {' '.join(f.tags)}".lower()
    for kw, category in KEYWORD_HINTS:
        if kw in haystack:
            return category
    return "misconfig"


def build_threat_model(session: Session) -> ThreatModel:
    tm = ThreatModel(target=session.target)
    for f in session.findings:
        category = _infer_category(f)
        exploitability, module = EXPLOIT_MAP.get(category, (0.2, None))
        sev_w = SEVERITY_WEIGHT.get(f.severity, 1)
        # score blends impact (severity) with ease of weaponization
        score = sev_w * (0.5 + 0.5 * exploitability)
        tm.nodes.append(AttackNode(
            finding=f,
            category=category,
            score=score,
            exploitability=exploitability,
            exploit_module=module,
        ))
    tm.nodes.sort(key=lambda n: n.score, reverse=True)
    return tm


def display(tm: ThreatModel):
    console.print()
    console.print(Panel(
        f"[bold white]{tm.target}[/bold white]  "
        f"[dim]attack surface:[/dim] {len(tm.nodes)} findings  "
        f"[dim]actionable:[/dim] [red]{len(tm.actionable)}[/red]",
        title="[bold red]Threat Model — Attack Plan[/bold red]",
        border_style="red", expand=False,
    ))
    if not tm.nodes:
        console.print("[dim]    No findings to model. Run recon/vulnscan first.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("#", width=3, justify="right")
    table.add_column("Score", width=6)
    table.add_column("Sev", width=9)
    table.add_column("Category", style="cyan", width=14)
    table.add_column("Finding", style="white", min_width=28)
    table.add_column("Next action", style="yellow", width=22)

    for i, n in enumerate(tm.nodes[:25], 1):
        action = f"exploitation/{n.exploit_module}" if n.exploit_module else "manual / report"
        table.add_row(
            str(i), f"{n.score:.1f}", n.finding.severity, n.category,
            n.finding.title[:40], action,
        )
    console.print(table)
    console.print()


def run_threat_model(session: Optional[Session] = None, save_json: Optional[str] = None) -> ThreatModel:
    """Build and display the prioritized attack plan for the active session."""
    from core.session import get_session
    session = session or get_session()
    if session is None:
        console.print("[yellow][!] No active session.[/yellow]")
        return ThreatModel(target="unknown")

    tm = build_threat_model(session)
    display(tm)
    session.set_meta("threat_model", tm.to_dict())

    if save_json:
        import json
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(tm.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")
    return tm
