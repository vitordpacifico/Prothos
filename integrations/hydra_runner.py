import asyncio
import json
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
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
class HydraCredential:
    host:       str
    service:    str
    username:   str
    password:   str
    severity:   str          = "critical"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class HydraReport:
    target:      str
    service:     str
    started_at:  str                    = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]         = None
    command:     str                   = ""
    credentials: list[HydraCredential] = field(default_factory=list)
    errors:      list[str]             = field(default_factory=list)

    @property
    def critical(self) -> list[HydraCredential]:
        return [c for c in self.credentials if c.severity == "critical"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["credentials"] = [c.to_dict() for c in self.credentials]
        return d


HOST_RE = re.compile(r"host:\s*(\S+)", re.IGNORECASE)
LOGIN_RE = re.compile(r"login:\s*(\S+)", re.IGNORECASE)
PASS_RE = re.compile(r"password:\s*(\S+)", re.IGNORECASE)


def _print_cred(c: HydraCredential):
    console.print(
        f"  [bold red][CRITICAL][/bold red] "
        f"[bold white]{c.username}[/bold white]:[yellow]{c.password}[/yellow] "
        f"[dim]@ {c.host} ({c.service})[/dim]"
    )


def _display(report: HydraReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]service:[/dim] {report.service}  "
        f"[dim]valid creds:[/dim] [red]{len(report.credentials)}[/red]",
        title="[bold red]hydra Runner — Summary[/bold red]",
        border_style="red",
    ))

    if not report.credentials:
        console.print("[dim]    No valid credentials found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Host",     style="cyan", width=24)
    table.add_column("Service",  style="magenta", width=12)
    table.add_column("Username", style="bold white", width=20)
    table.add_column("Password", style="yellow", min_width=18)

    for c in report.credentials:
        table.add_row(c.host, c.service, c.username, c.password)

    console.print(table)
    console.print()


async def _run_async(target, service, userlist, passlist, username, password,
                     port, threads, form_spec, extra_args) -> HydraReport:
    report = HydraReport(target=target, service=service)

    binary = shutil.which("hydra")
    if not binary:
        report.errors.append("hydra not found in PATH")
        console.print("[red][!] hydra not installed — https://github.com/vanhauser-thc/thc-hydra[/red]")
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report

    parsed = urlparse(target if "://" in target else f"//{target}")
    host = parsed.hostname or target

    args = [binary]
    if username:
        args += ["-l", username]
    elif userlist:
        args += ["-L", userlist]
    if password:
        args += ["-p", password]
    elif passlist:
        args += ["-P", passlist]
    if port:
        args += ["-s", str(port)]
    args += ["-t", str(threads), "-I", "-f"]
    if extra_args:
        args += extra_args

    if service in ("http-post-form", "https-post-form", "http-get-form") and form_spec:
        args += [host, service, form_spec]
    else:
        args += [f"{service}://{host}"]

    report.command = " ".join(args)

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[bold white]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Running hydra...", total=None)
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            assert proc.stdout is not None
            async for raw in proc.stdout:
                line = raw.decode("utf-8", "replace").strip()
                if "login:" in line.lower() and "password:" in line.lower():
                    h = HOST_RE.search(line)
                    lo = LOGIN_RE.search(line)
                    pw = PASS_RE.search(line)
                    cred = HydraCredential(
                        host=h.group(1) if h else host,
                        service=service,
                        username=lo.group(1) if lo else "?",
                        password=pw.group(1) if pw else "?",
                    )
                    report.credentials.append(cred)
                    _print_cred(cred)
            await proc.wait()
        except Exception as e:
            report.errors.append(str(e)[:200])

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_hydra_runner(
    target:      str,
    service:     str                 = "ssh",
    userlist:    Optional[str]       = None,
    passlist:    Optional[str]       = None,
    username:    Optional[str]       = None,
    password:    Optional[str]       = None,
    port:        Optional[int]       = None,
    threads:     int                 = 4,
    form_spec:   Optional[str]       = None,
    extra_args:  Optional[list[str]] = None,
    proxy:       Optional[str]       = None,
    save_json:   Optional[str]       = None,
) -> HydraReport:

    console.print(f"\n[bold red][*][/bold red] hydra Runner → [bold white]{target}[/bold white]")
    console.print(f"[dim]    service={service} threads={threads} "
                  f"user={'list' if userlist else (username or '-')} "
                  f"pass={'list' if passlist else ('single' if password else '-')}[/dim]")

    report = asyncio.run(_run_async(target, service, userlist, passlist, username,
                                    password, port, threads, form_spec, extra_args))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
