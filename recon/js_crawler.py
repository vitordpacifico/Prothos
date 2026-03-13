import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

RE_ENDPOINT = re.compile(
    r'(?:"|\'|`)((?:https?://|/)[a-zA-Z0-9_\-/\.:%@!~,;=?&#+]+)(?:"|\'|`)'
)

RE_API_PATH = re.compile(
    r'(?:"|\'|`)(/(?:api|v\d|graphql|rest|internal|admin|auth)[a-zA-Z0-9_\-/\.:%@!~,;=?&#+]*)(?:"|\'|`)'
)

RE_FULL_URL = re.compile(
    r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
)

RE_SECRETS = [
    (re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.I), "API Key"),
    (re.compile(r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']([A-Za-z0-9_\-]{8,})["\']', re.I), "Secret/Token"),
    (re.compile(r'(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']', re.I), "Auth Token"),
    (re.compile(r'AKIA[0-9A-Z]{16}', re.I), "AWS Access Key"),
    (re.compile(r'(?:aws[_-]?secret|aws[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{32,})["\']', re.I), "AWS Secret"),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', re.I), "Private Key"),
    (re.compile(r'(?:firebase|fb)[_-]?(?:key|token|secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.I), "Firebase Key"),
    (re.compile(r'AIza[0-9A-Za-z_\-]{35}', re.I), "Google API Key"),
    (re.compile(r'(?:slack[_-]?token|xox[baprs]-[0-9A-Za-z\-]+)', re.I), "Slack Token"),
    (re.compile(r'(?:stripe[_-]?(?:key|secret|pk|sk))\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.I), "Stripe Key"),
    (re.compile(r'(?:mapbox[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{32,})["\']', re.I), "Mapbox Token"),
    (re.compile(r'(?:twilio[_-]?(?:sid|token|key))\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.I), "Twilio Key"),
    (re.compile(r'(?:gh[pousr]_[A-Za-z0-9_]{36,})', re.I), "GitHub Token"),
    (re.compile(r'(?:npm[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.I), "NPM Token"),
]

IGNORE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz",
    ".map",
}

@dataclass
class SecretFinding:
    js_url:   str
    kind:     str
    value:    str
    line:     int   = 0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class JSScanReport:
    target:       str
    started_at:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:  Optional[str] = None
    js_files:     list[str]          = field(default_factory=list)
    endpoints:    list[str]          = field(default_factory=list)
    internal_apis:list[str]          = field(default_factory=list)
    external_urls:list[str]          = field(default_factory=list)
    secrets:      list[SecretFinding]= field(default_factory=list)
    errors:       list[str]          = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["secrets"] = [s.to_dict() for s in self.secrets]
        return d

def _is_same_domain(url: str, target: str) -> bool:
    target_host = urlparse(target).netloc.lower().lstrip("www.")
    url_host    = urlparse(url).netloc.lower().lstrip("www.")
    return url_host == target_host or url_host.endswith("." + target_host)


def _should_ignore(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in IGNORE_EXTENSIONS)


def _extract_endpoints(js_text: str, target: str, js_url: str) -> tuple[set[str], set[str], set[str]]:
    """
    Extrai endpoints do conteúdo JS.
    Retorna: (endpoints_internos, apis, externos)
    """
    internal = set()
    apis     = set()
    external = set()
    target_host = urlparse(target).netloc

    candidates = set()
    candidates.update(RE_ENDPOINT.findall(js_text))
    candidates.update(RE_API_PATH.findall(js_text))
    candidates.update(RE_FULL_URL.findall(js_text))

    for raw in candidates:
        raw = raw.strip().rstrip("\"',`")

        if raw.startswith("/"):
            url = urljoin(target, raw)
        elif raw.startswith("http"):
            url = raw
        else:
            continue

        if _should_ignore(url):
            continue

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue

        path_lower = parsed.path.lower()

        if _is_same_domain(url, target):
            if any(seg in path_lower for seg in ["/api/", "/v1/", "/v2/", "/v3/",
                                                  "/graphql", "/rest/", "/internal/",
                                                  "/admin/", "/auth/"]):
                apis.add(url)
            else:
                internal.add(url)
        else:
            external.add(url)

    return internal, apis, external


def _scan_for_secrets(js_text: str, js_url: str) -> list[SecretFinding]:
    findings = []
    lines    = js_text.splitlines()

    for i, line in enumerate(lines, 1):
        for pattern, kind in RE_SECRETS:
            m = pattern.search(line)
            if m:
                value = m.group(0)[:60] + ("..." if len(m.group(0)) > 60 else "")
                findings.append(SecretFinding(
                    js_url=js_url,
                    kind=kind,
                    value=value,
                    line=i,
                ))
                break

    return findings


async def _fetch_js(
    client:  httpx.AsyncClient,
    js_url:  str,
    target:  str,
    sem:     asyncio.Semaphore,
    max_size:int = 2_000_000,
) -> tuple[set[str], set[str], set[str], list[SecretFinding], Optional[str]]:
    """Baixa e analisa um único arquivo JS."""
    async with sem:
        try:
            r = await client.get(js_url, timeout=15)
            if r.status_code != 200:
                return set(), set(), set(), [], None

            content_len = int(r.headers.get("content-length", 0))
            if content_len > max_size or len(r.content) > max_size:
                return set(), set(), set(), [], f"Skipped (too large: {len(r.content) // 1024}KB)"

            js_text  = r.text
            internal, apis, external = _extract_endpoints(js_text, target, js_url)
            secrets  = _scan_for_secrets(js_text, js_url)
            return internal, apis, external, secrets, None

        except httpx.TimeoutException:
            return set(), set(), set(), [], "Timeout"
        except Exception as e:
            return set(), set(), set(), [], str(e)[:80]


async def _js_scan_async(
    target:      str,
    concurrency: int = 20,
    proxy:       Optional[str] = None,
    deep:        bool = False,
) -> JSScanReport:

    report  = JSScanReport(target=target)
    proxies = {"http://": proxy, "https://": proxy} if proxy else None

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        },
        proxies=proxies,
    ) as client:

        try:
            r = await client.get(target, timeout=15)
            r.raise_for_status()
        except Exception as e:
            report.errors.append(f"Failed to fetch target: {e}")
            console.print(f"[red][!] Failed to fetch target: {e}[/red]")
            return report

        soup    = BeautifulSoup(r.text, "lxml")
        js_urls = set()

        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "").strip()
            if src:
                full = urljoin(target, src)
                if deep or _is_same_domain(full, target):
                    js_urls.add(full)

        inline_endpoints = set()
        inline_apis      = set()
        inline_external  = set()
        inline_secrets   = []

        for tag in soup.find_all("script", src=False):
            content = tag.string or ""
            if len(content) > 50:
                i, a, e = _extract_endpoints(content, target, f"{target}#inline")
                s        = _scan_for_secrets(content, f"{target}#inline")
                inline_endpoints.update(i)
                inline_apis.update(a)
                inline_external.update(e)
                inline_secrets.extend(s)

        report.js_files = sorted(js_urls)
        console.print(f"[dim]    Found {len(js_urls)} JS files + inline scripts[/dim]\n")

        sem   = asyncio.Semaphore(concurrency)
        tasks = [_fetch_js(client, js_url, target, sem) for js_url in js_urls]

        all_internal = inline_endpoints
        all_apis     = inline_apis
        all_external = inline_external
        all_secrets  = inline_secrets

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=35, style="red", complete_style="green"),
            TextColumn("[green]{task.completed}[/green]/[white]{task.total}[/white]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Analyzing JS files...", total=len(tasks))

            for coro in asyncio.as_completed(tasks):
                internal, apis, external, secrets, err = await coro
                all_internal.update(internal)
                all_apis.update(apis)
                all_external.update(external)
                all_secrets.extend(secrets)
                if err:
                    report.errors.append(err)
                progress.advance(task_id, 1)

    report.endpoints     = sorted(all_internal | all_apis)
    report.internal_apis = sorted(all_apis)
    report.external_urls = sorted(all_external)
    report.secrets       = all_secrets
    report.finished_at   = datetime.now(timezone.utc).isoformat()
    return report

def _display_results(report: JSScanReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]js files:[/dim] [white]{len(report.js_files)}[/white]  "
        f"[dim]endpoints:[/dim] [green]{len(report.endpoints)}[/green]  "
        f"[dim]apis:[/dim] [cyan]{len(report.internal_apis)}[/cyan]  "
        f"[dim]external:[/dim] [yellow]{len(report.external_urls)}[/yellow]  "
        f"[dim]secrets:[/dim] [{'red' if report.secrets else 'dim'}]{len(report.secrets)}[/{'red' if report.secrets else 'dim'}]",
        title="[bold red]JS Crawler — Summary[/bold red]",
        border_style="red",
    ))

    if report.js_files:
        console.print(f"\n[bold yellow]JS Files ({len(report.js_files)})[/bold yellow]")
        for js in report.js_files:
            console.print(f"  [dim]•[/dim] {js}")

    if report.internal_apis:
        console.print(f"\n[bold cyan]API Endpoints ({len(report.internal_apis)})[/bold cyan]")
        for ep in report.internal_apis:
            console.print(f"  [cyan]→[/cyan] [bold white]{ep}[/bold white]")

    other = [e for e in report.endpoints if e not in report.internal_apis]
    if other:
        console.print(f"\n[bold white]Endpoints ({len(other)})[/bold white]")
        for ep in other:
            console.print(f"  [green]✓[/green] {ep}")

    if report.external_urls:
        console.print(f"\n[bold yellow]External URLs ({len(report.external_urls)})[/bold yellow]")
        for url in report.external_urls[:20]:
            console.print(f"  [yellow]↗[/yellow] [dim]{url}[/dim]")
        if len(report.external_urls) > 20:
            console.print(f"  [dim]... and {len(report.external_urls) - 20} more[/dim]")

    if report.secrets:
        console.print(f"\n[bold red blink][!] POTENTIAL SECRETS FOUND: {len(report.secrets)}[/bold red blink]")
        table = Table(show_header=True, header_style="bold red", border_style="dim")
        table.add_column("Type",    style="bold red",   width=20)
        table.add_column("Value",   style="yellow",     min_width=40)
        table.add_column("Line",    style="dim",        width=6)
        table.add_column("File",    style="dim italic", min_width=30)
        for s in report.secrets:
            table.add_row(s.kind, s.value, str(s.line), s.js_url.split("/")[-1] or s.js_url)
        console.print(table)

    if report.errors:
        console.print(f"\n[dim][!] Errors: {len(report.errors)}[/dim]")

    console.print()

def run_js_scan(
    target:      str,
    concurrency: int           = 20,
    deep:        bool          = False,
    proxy:       Optional[str] = None,
    save_json:   Optional[str] = None,
) -> JSScanReport:
    
    console.print(f"\n[bold red][*][/bold red] JS Scan → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Concurrency: {concurrency}  Deep: {deep}[/dim]\n")

    report = asyncio.run(_js_scan_async(
        target=target,
        concurrency=concurrency,
        proxy=proxy,
        deep=deep,
    ))

    _display_results(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save JSON: {e}[/red]")

    return report