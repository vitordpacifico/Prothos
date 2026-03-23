import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

@dataclass
class VHostResult:
    vhost:         str
    status:        int
    content_len:   int                = 0
    title:         Optional[str]      = None
    server:        Optional[str]      = None
    response_time: float              = 0.0
    different:     bool               = False
    interesting:   bool               = False
    notes:         list[str]          = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class VHostReport:
    target:      str
    ip:          str                          = ""
    started_at:  str                          = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]               = None
    total_tested: int                         = 0
    found:       list[VHostResult]            = field(default_factory=list)
    errors:      list[str]                   = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["found"] = [r.to_dict() for r in self.found]
        return d

async def _get_baseline(
    client: httpx.AsyncClient,
    target: str,
    host:   str,
) -> tuple[int, int, str]:

    try:
        r = await client.get(target, headers={"Host": host}, timeout=10)
        return r.status_code, len(r.content), r.text[:200]
    except Exception:
        return 0, 0, ""

def _build_vhosts(domain: str, wordlist: list[str]) -> list[str]:
    """Gera lista de vhosts para testar baseado no domínio."""
    vhosts = []
    for word in wordlist:
        vhosts.append(f"{word}.{domain}")
    return vhosts


DEFAULT_WORDLIST = [
    "admin", "api", "app", "apps", "auth", "backend", "beta",
    "blog", "cdn", "chat", "ci", "cloud", "cms", "console",
    "control", "cp", "dashboard", "data", "db", "dev", "dev2",
    "demo", "docs", "email", "erp", "ftp", "git", "gitlab",
    "helpdesk", "internal", "intranet", "jenkins", "jira",
    "kibana", "legacy", "login", "mail", "manage", "manager",
    "monitoring", "mq", "mx", "mysql", "new", "old", "ops",
    "panel", "portal", "preprod", "prod", "prometheus", "proxy",
    "rabbitmq", "redis", "registry", "remote", "repo", "reports",
    "sandbox", "secrets", "secure", "security", "service",
    "services", "shop", "smtp", "sql", "ssh", "stage", "staging",
    "static", "status", "support", "test", "testing", "tools",
    "vault", "vpn", "web", "webmail", "wiki", "www", "www2",
]

import re

def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:80] if m else None


async def _probe(
    client:       httpx.AsyncClient,
    target:       str,
    vhost:        str,
    sem:          asyncio.Semaphore,
    baseline:     tuple[int, int, str],
) -> Optional[VHostResult]:

    baseline_status, baseline_len, baseline_body = baseline

    async with sem:
        import time
        try:
            t0 = time.perf_counter()
            r  = await client.get(
                target,
                headers={"Host": vhost},
                timeout=10,
            )
            elapsed = round(time.perf_counter() - t0, 3)

            headers     = {k.lower(): v for k, v in r.headers.items()}
            content_len = len(r.content)
            body        = r.text
            title       = _extract_title(body)
            server      = headers.get("server")

            status_diff  = r.status_code != baseline_status
            len_diff     = abs(content_len - baseline_len) > 200
            body_diff    = body[:200] != baseline_body

            different = status_diff or (len_diff and body_diff)

            if not different:
                return None

            notes       = []
            interesting = False

            if r.status_code in (200, 201):
                notes.append("200 OK")
                interesting = True
            elif r.status_code in (401, 403):
                notes.append("Auth required")
                interesting = True
            elif r.status_code in (301, 302, 307, 308):
                loc = headers.get("location", "")
                notes.append(f"Redirect → {loc[:40]}")
            elif r.status_code == 500:
                notes.append("Server error")
                interesting = True

            if server:
                notes.append(f"Server: {server}")

            return VHostResult(
                vhost=vhost,
                status=r.status_code,
                content_len=content_len,
                title=title,
                server=server,
                response_time=elapsed,
                different=different,
                interesting=interesting,
                notes=notes,
            )

        except httpx.TimeoutException:
            return None
        except Exception:
            return None

def _status_color(status: int) -> str:
    if status < 300:  return "green"
    if status < 400:  return "yellow"
    if status < 500:  return "cyan"
    return "red"


def _display(report: VHostReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]tested:[/dim] {report.total_tested}  "
        f"[dim]found:[/dim] [green]{len(report.found)}[/green]",
        title="[bold red]VHost Enum — Summary[/bold red]",
        border_style="red",
    ))

    if not report.found:
        console.print("[dim]    No virtual hosts found.[/dim]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold red",
        border_style="dim",
    )
    table.add_column("Status",  width=8)
    table.add_column("VHost",   min_width=35)
    table.add_column("Title",   min_width=25, style="dim italic")
    table.add_column("Size",    width=8,  style="dim")
    table.add_column("Time",    width=7,  style="dim")
    table.add_column("Notes",   min_width=20, style="yellow")

    for r in report.found:
        color  = _status_color(r.status)
        table.add_row(
            f"[{color}]{r.status}[/{color}]",
            r.vhost,
            r.title or "-",
            f"{r.content_len}b",
            f"{r.response_time}s",
            " | ".join(r.notes[:2]) if r.notes else "-",
        )

    console.print(table)
    console.print()

async def _vhost_async(
    target:      str,
    domain:      str,
    wordlist:    list[str],
    concurrency: int,
    proxy:       Optional[str],
) -> VHostReport:

    report  = VHostReport(target=target)
    sem     = asyncio.Semaphore(concurrency)
    vhosts  = _build_vhosts(domain, wordlist)
    report.total_tested = len(vhosts)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        console.print(f"[dim]    Getting baseline response...[/dim]")
        baseline = await _get_baseline(client, target, domain)
        console.print(f"[dim]    Baseline: status={baseline[0]} len={baseline[1]}b[/dim]")

        tasks   = [_probe(client, target, vh, sem, baseline) for vh in vhosts]

        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=35, style="red", complete_style="green"),
            TextColumn("[green]{task.completed}[/green]/[white]{task.total}[/white]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(f"Enumerating vhosts", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    report.found.append(result)
                    color = _status_color(result.status)
                    console.print(
                        f"  [{color}]{result.status}[/{color}] "
                        f"[bold white]{result.vhost}[/bold white]"
                        + (f" [dim italic]{result.title}[/dim italic]" if result.title else "")
                    )
                progress.advance(task_id)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_vhost_enum(
    target:       str,
    wordlist:     Optional[list[str]] = None,
    wordlist_path:Optional[str]       = None,
    concurrency:  int                 = 30,
    proxy:        Optional[str]       = None,
    save_json:    Optional[str]       = None,
) -> VHostReport:
    parsed = urlparse(target)
    domain = parsed.netloc

    console.print(f"\n[bold red][*][/bold red] VHost Enum → [bold white]{target}[/bold white]")

    if wordlist_path:
        try:
            from utils.wordlist_loader import load_wordlist
            wordlist = load_wordlist(wordlist_path)
        except Exception as e:
            console.print(f"[red][!] Failed to load wordlist: {e}[/red]")
            wordlist = DEFAULT_WORDLIST
    elif not wordlist:
        wordlist = DEFAULT_WORDLIST

    console.print(f"[dim]    Wordlist: {len(wordlist)} entries  Concurrency: {concurrency}[/dim]")

    report = asyncio.run(_vhost_async(
        target=target,
        domain=domain,
        wordlist=wordlist,
        concurrency=concurrency,
        proxy=proxy,
    ))

    _display(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report