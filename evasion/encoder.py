import base64
import json
import html as html_lib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

ALL_TECHNIQUES = [
    "url", "double_url", "html_entity", "html_entity_hex", "unicode",
    "hex", "hex_percent", "base64", "base64_url", "mixed_url_base64",
    "mixed_unicode_html",
]


@dataclass
class EncodedVariant:
    technique:  str
    value:      str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class EncoderReport:
    payload:     str
    started_at:  str                     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]          = None
    variants:    list[EncodedVariant]   = field(default_factory=list)
    errors:      list[str]              = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["variants"] = [v.to_dict() for v in self.variants]
        return d


def _url(s: str) -> str:
    return quote(s, safe="")


def _double_url(s: str) -> str:
    return quote(quote(s, safe=""), safe="")


def _html_entity(s: str) -> str:
    return html_lib.escape(s, quote=True)


def _html_entity_hex(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in s)


def _unicode(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)


def _hex(s: str) -> str:
    return "".join(f"\\x{ord(c):02x}" for c in s)


def _hex_percent(s: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in s)


def _base64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _base64_url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()


def _mixed_url_base64(s: str) -> str:
    return quote(base64.b64encode(s.encode()).decode(), safe="")


def _mixed_unicode_html(s: str) -> str:
    out = []
    for i, c in enumerate(s):
        if i % 2 == 0:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(f"&#x{ord(c):x};")
    return "".join(out)


ENCODERS = {
    "url":                _url,
    "double_url":         _double_url,
    "html_entity":        _html_entity,
    "html_entity_hex":    _html_entity_hex,
    "unicode":            _unicode,
    "hex":                _hex,
    "hex_percent":        _hex_percent,
    "base64":             _base64,
    "base64_url":         _base64_url,
    "mixed_url_base64":   _mixed_url_base64,
    "mixed_unicode_html": _mixed_unicode_html,
}


def _display(report: EncoderReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.payload[:60]}[/bold white]  "
        f"[dim]variants:[/dim] [yellow]{len(report.variants)}[/yellow]",
        title="[bold red]Encoder — Summary[/bold red]",
        border_style="red",
    ))

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Technique", style="cyan", width=20)
    table.add_column("Encoded",   style="yellow", min_width=40)

    for v in report.variants:
        table.add_row(v.technique, v.value[:90])

    console.print(table)
    console.print()


def run_encoder(
    payload:     str,
    techniques:  Optional[list[str]] = None,
    save_json:   Optional[str]       = None,
) -> EncoderReport:

    report = EncoderReport(payload=payload)
    selected = techniques or ALL_TECHNIQUES

    console.print(f"\n[bold red][*][/bold red] Encoder → [bold white]{payload[:50]}[/bold white]")
    console.print(f"[dim]    Techniques: {len(selected)}[/dim]")

    for tech in selected:
        fn = ENCODERS.get(tech)
        if not fn:
            report.errors.append(f"unknown technique: {tech}")
            continue
        try:
            report.variants.append(EncodedVariant(technique=tech, value=fn(payload)))
        except Exception as e:
            report.errors.append(f"{tech}: {str(e)[:60]}")

    report.finished_at = datetime.now(timezone.utc).isoformat()
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
