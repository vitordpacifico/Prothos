import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from recon.subdomain_bruteforce import run_subdomain_bruteforce, BruteforceReport
from recon.passive_subdomains import run_passive_subdomain_scan, PassiveScanReport

console = Console()

@dataclass
class SubdomainEngineReport:
    domain:         str
    started_at:     str           = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:    Optional[str] = None
    bruteforce:     Optional[BruteforceReport]    = None
    passive:        Optional[PassiveScanReport]   = None
    all_subdomains: list[str]     = field(default_factory=list)
    unique_count:   int           = 0
    only_bruteforce:list[str]     = field(default_factory=list)
    only_passive:   list[str]     = field(default_factory=list)
    confirmed_both: list[str]     = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["bruteforce"] = self.bruteforce.to_dict() if self.bruteforce else None
        d["passive"]    = self.passive.to_dict()    if self.passive    else None
        return d

def run_subbrute_engine(
    domain:           str,
    wordlist_path:    str          = "wordlists/subdomains.txt",
    concurrency:      int          = 100,
    http_probe:       bool         = True,
    use_bruteforce:   bool         = True,
    use_passive:      bool         = True,
    resolvers:        list[str]    = None,
    proxy:            Optional[str]= None,
    save_json:        Optional[str]= None,
) -> SubdomainEngineReport:

    report = SubdomainEngineReport(domain=domain)

    console.print(f"\n[bold red][*][/bold red] Subdomain Engine → [bold white]{domain}[/bold white]")
    console.print(
        f"[dim]    Bruteforce: {use_bruteforce}  "
        f"Passive: {use_passive}  "
        f"HTTP probe: {http_probe}[/dim]\n"
    )

    brute_subs:   set[str] = set()
    passive_subs: set[str] = set()

    if use_bruteforce:
        console.print("[bold red][1/2][/bold red] Running bruteforce...\n")
        brute_report = run_subdomain_bruteforce(
            domain=domain,
            wordlist_path=wordlist_path,
            concurrency=concurrency,
            http_probe=http_probe,
            resolvers=resolvers,
        )
        report.bruteforce = brute_report
        brute_subs = {r.subdomain for r in brute_report.found}

    if use_passive:
        console.print("\n[bold red][2/2][/bold red] Running passive scan...\n")
        passive_report = run_passive_subdomain_scan(
            domain=domain,
            http_probe=http_probe,
        )
        report.passive = passive_report
        passive_subs = {r.subdomain for r in passive_report.found}

    all_subs = brute_subs | passive_subs

    report.all_subdomains = sorted(all_subs)
    report.unique_count   = len(all_subs)
    report.confirmed_both = sorted(brute_subs & passive_subs)
    report.only_bruteforce= sorted(brute_subs - passive_subs)
    report.only_passive   = sorted(passive_subs - brute_subs)
    report.finished_at    = datetime.now(timezone.utc).isoformat()

    _display_summary(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save JSON: {e}[/red]")

    return report

def _display_summary(report: SubdomainEngineReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.domain}[/bold white]\n"
        f"[dim]total unique:[/dim]   [bold green]{report.unique_count}[/bold green]\n"
        f"[dim]confirmed both:[/dim] [bold cyan]{len(report.confirmed_both)}[/bold cyan]  "
        f"[dim](bruteforce + passive — higher confidence)[/dim]\n"
        f"[dim]only bruteforce:[/dim][yellow]{len(report.only_bruteforce)}[/yellow]  "
        f"[dim]only passive:[/dim]   [yellow]{len(report.only_passive)}[/yellow]",
        title="[bold red]Subdomain Engine — Final Report[/bold red]",
        border_style="red",
    ))

    if report.confirmed_both:
        console.print(f"\n[bold cyan]Confirmed by both sources ({len(report.confirmed_both)})[/bold cyan]")
        for sub in report.confirmed_both:
            console.print(f"  [cyan]✓✓[/cyan] [bold white]{sub}[/bold white]")

    if report.only_bruteforce:
        console.print(f"\n[bold yellow]Only bruteforce ({len(report.only_bruteforce)})[/bold yellow]")
        for sub in report.only_bruteforce[:20]:
            console.print(f"  [green]✓[/green] {sub}")
        if len(report.only_bruteforce) > 20:
            console.print(f"  [dim]... and {len(report.only_bruteforce) - 20} more[/dim]")

    if report.only_passive:
        console.print(f"\n[bold yellow]Only passive ({len(report.only_passive)})[/bold yellow]")
        for sub in report.only_passive[:20]:
            console.print(f"  [green]✓[/green] {sub}")
        if len(report.only_passive) > 20:
            console.print(f"  [dim]... and {len(report.only_passive) - 20} more[/dim]")

    console.print()