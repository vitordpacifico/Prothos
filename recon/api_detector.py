import asyncio
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

console = Console()

RE_SCRIPT_SRC = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

RE_SCRIPT_INLINE = re.compile(
    r'<script(?![^>]+src=)[^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)

RE_WEBPACK_CHUNK = re.compile(
    r'(?:chunkFilename|chunk-)["\']?\s*[:+]\s*["\']([^"\']+\.js)["\']'
)

RE_SOURCEMAP = re.compile(
    r'//[#@]\s*sourceMappingURL=([^\s]+\.map)'
)

RE_LAZY_LOAD = re.compile(
    r'(?:fetch|axios\.get|\.get)\s*\(\s*["\']([^"\']+\.js)["\']'
)

INTERESTING_PATTERNS = {
    "auth":     r'auth|login|oauth|token|session|sso|jwt',
    "api":      r'api|graphql|rest|endpoint|service',
    "admin":    r'admin|backoffice|dashboard|panel|console',
    "config":   r'config|settings|env|constants|secret',
    "vendor":   r'vendor|chunk|bundle|runtime|polyfill|common',
    "payment":  r'payment|billing|stripe|checkout|wallet',
    "upload":   r'upload|file|media|storage|blob',
    "internal": r'internal|private|hidden|legacy|old|bak',
}
@dataclass
class JSFile:
    url:           str
    kind:          str             = "external"
    size:          Optional[int]   = None
    status:        Optional[int]   = None
    content_type:  Optional[str]   = None
    source_map:    Optional[str]   = None
    categories:    list[str]       = field(default_factory=list)
    interesting:   bool            = False
    same_domain:   bool            = True
    response_time: Optional[float] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class JSDiscoveryReport:
    target:        str
    started_at:    str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:   Optional[str]  = None
    js_files:      list[JSFile]   = field(default_factory=list)
    inline_count:  int            = 0
    errors:        list[str]      = field(default_factory=list)

    @property
    def external(self)    -> list[JSFile]: return [f for f in self.js_files if f.kind == "external"]
    @property
    def chunks(self)      -> list[JSFile]: return [f for f in self.js_files if f.kind == "chunk"]
    @property
    def sourcemaps(self)  -> list[JSFile]: return [f for f in self.js_files if f.source_map]
    @property
    def interesting(self) -> list[JSFile]: return [f for f in self.js_files if f.interesting]
    @property
    def third_party(self) -> list[JSFile]: return [f for f in self.js_files if not f.same_domain]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["js_files"] = [f.to_dict() for f in self.js_files]
        return d

def _is_same_domain(url: str, target: str) -> bool:
    target_host = urlparse(target).netloc.lower().lstrip("www.")
    url_host    = urlparse(url).netloc.lower().lstrip("www.")
    return url_host == target_host or url_host.endswith("." + target_host)


def _classify(url: str) -> tuple[list[str], bool]:
    """Classifica o JS por categoria e se é interessante."""
    filename   = urlparse(url).path.lower().split("/")[-1]
    categories = []
    for cat, pattern in INTERESTING_PATTERNS.items():
        if re.search(pattern, filename, re.IGNORECASE):
            categories.append(cat)

    interesting = bool(categories) and not (
        len(categories) == 1 and categories[0] == "vendor"
    )
    return categories, interesting


async def _probe_js(
    client:  httpx.AsyncClient,
    js_file: JSFile,
    target:  str,
    sem:     asyncio.Semaphore,
) -> JSFile:

    async with sem:
        import time
        try:
            t0 = time.perf_counter()
            r  = await client.head(js_file.url, timeout=8)
            elapsed = round(time.perf_counter() - t0, 3)

            js_file.status        = r.status_code
            js_file.content_type  = r.headers.get("content-type", "")[:60]
            js_file.response_time = elapsed

            cl = r.headers.get("content-length")
            if cl:
                js_file.size = int(cl)

            map_url = js_file.url + ".map"
            try:
                rm = await client.head(map_url, timeout=5)
                if rm.status_code == 200:
                    js_file.source_map = map_url
                    js_file.interesting = True
                    if "sourcemap" not in js_file.categories:
                        js_file.categories.append("sourcemap ⚠")
            except Exception:
                pass

        except Exception as e:
            js_file.errors = [str(e)[:60]] if hasattr(js_file, "errors") else []

    return js_file

async def _find_js_async(
    target:      str,
    probe:       bool,
    concurrency: int,
    proxy:       Optional[str],
) -> JSDiscoveryReport:

    report  = JSDiscoveryReport(target=target)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
        },
        proxy=proxy,
    ) as client:

        try:
            r = await client.get(target, timeout=15)
            r.raise_for_status()
        except Exception as e:
            report.errors.append(f"Failed to fetch target: {e}")
            console.print(f"[red][!] {e}[/red]")
            return report

        html = r.text
        soup = BeautifulSoup(html, "lxml")
        seen: set[str] = set()
        js_files: list[JSFile] = []

        for m in RE_SCRIPT_SRC.finditer(html):
            src = m.group(1).strip()
            if not src or src.startswith("data:"):
                continue
            full = urljoin(target, src)
            if full in seen:
                continue
            seen.add(full)
            cats, interesting = _classify(full)
            js_files.append(JSFile(
                url=full,
                kind="external",
                categories=cats,
                interesting=interesting,
                same_domain=_is_same_domain(full, target),
            ))

        for m in RE_WEBPACK_CHUNK.finditer(html):
            chunk_path = m.group(1).strip()
            full = urljoin(target, chunk_path)
            if full in seen:
                continue
            seen.add(full)
            cats, _ = _classify(full)
            js_files.append(JSFile(
                url=full,
                kind="chunk",
                categories=cats,
                interesting=True,
                same_domain=_is_same_domain(full, target),
            ))

        for m in RE_LAZY_LOAD.finditer(html):
            lazy_path = m.group(1).strip()
            full = urljoin(target, lazy_path)
            if full in seen:
                continue
            seen.add(full)
            cats, interesting = _classify(full)
            js_files.append(JSFile(
                url=full,
                kind="lazy",
                categories=cats,
                interesting=interesting,
                same_domain=_is_same_domain(full, target),
            ))

        for m in RE_SOURCEMAP.finditer(html):
            map_path = m.group(1).strip()
            full = urljoin(target, map_path)
            if full in seen:
                continue
            seen.add(full)
            js_files.append(JSFile(
                url=full,
                kind="sourcemap",
                categories=["sourcemap ⚠"],
                interesting=True,
                same_domain=_is_same_domain(full, target),
            ))

        inline_scripts = RE_SCRIPT_INLINE.findall(html)
        report.inline_count = sum(1 for s in inline_scripts if len(s.strip()) > 50)

        for inline in inline_scripts:
            for m in RE_WEBPACK_CHUNK.finditer(inline):
                chunk_path = m.group(1).strip()
                full = urljoin(target, chunk_path)
                if full not in seen:
                    seen.add(full)
                    cats, _ = _classify(full)
                    js_files.append(JSFile(
                        url=full,
                        kind="chunk",
                        categories=cats,
                        interesting=True,
                        same_domain=_is_same_domain(full, target),
                    ))

        report.js_files = js_files

        if probe and js_files:
            sem = asyncio.Semaphore(concurrency)
            probe_tasks = [_probe_js(client, f, target, sem) for f in js_files]
            report.js_files = await asyncio.gather(*probe_tasks)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report

def _display_results(report: JSDiscoveryReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]\n"
        f"[dim]external:[/dim] [white]{len(report.external)}[/white]  "
        f"[dim]chunks:[/dim] [white]{len(report.chunks)}[/white]  "
        f"[dim]inline:[/dim] [white]{report.inline_count}[/white]  "
        f"[dim]3rd party:[/dim] [yellow]{len(report.third_party)}[/yellow]  "
        f"[dim]source maps:[/dim] [{'red' if report.sourcemaps else 'dim'}]{len(report.sourcemaps)}[/{'red' if report.sourcemaps else 'dim'}]  "
        f"[dim]interesting:[/dim] [red]{len(report.interesting)}[/red]",
        title="[bold red]JS File Discovery[/bold red]",
        border_style="red",
    ))

    if not report.js_files:
        console.print("[dim]  No JS files found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Kind",       style="dim",        width=10)
    table.add_column("Status",     style="bold",        width=7)
    table.add_column("Size",       style="dim",         width=8)
    table.add_column("URL",        style="white",       min_width=50)
    table.add_column("Categories", style="cyan",        min_width=20)
    table.add_column("Map",        style="bold red",    width=5)

    for f in sorted(report.js_files, key=lambda x: (not x.interesting, x.url)):
        status = f"[green]{f.status}[/green]" if f.status == 200 else (
                 f"[red]{f.status}[/red]"     if f.status else "[dim]-[/dim]")
        size   = f"{f.size // 1024}KB" if f.size else "-"
        cats   = ", ".join(f.categories) if f.categories else "-"
        mapf   = "[red]⚠[/red]" if f.source_map else "-"
        flag   = " [bold red]★[/bold red]" if f.interesting else ""
        table.add_row(f.kind, status, size, f.url + flag, cats, mapf)

    console.print(table)

    if report.sourcemaps:
        console.print(f"\n[bold red][!] SOURCE MAPS EXPOSED — original source code accessible:[/bold red]")
        for f in report.sourcemaps:
            console.print(f"    [red]→[/red] {f.source_map or f.url}")

    if report.third_party:
        console.print(f"\n[bold yellow]Third-party JS ({len(report.third_party)})[/bold yellow]")
        for f in report.third_party:
            console.print(f"  [dim]↗[/dim] {f.url}")

    console.print()

async def find_js_files(
    target:      str,
    probe:       bool          = True,
    concurrency: int           = 20,
    proxy:       Optional[str] = None,
) -> JSDiscoveryReport:
    
    return await _find_js_async(
        target=target,
        probe=probe,
        concurrency=concurrency,
        proxy=proxy,
    )


def run_js_discovery(
    target:      str,
    probe:       bool          = True,
    concurrency: int           = 20,
    proxy:       Optional[str] = None,
) -> JSDiscoveryReport:

    console.print(f"\n[bold red][*][/bold red] JS Discovery → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Probe: {probe}  Concurrency: {concurrency}[/dim]\n")

    report = asyncio.run(_find_js_async(
        target=target,
        probe=probe,
        concurrency=concurrency,
        proxy=proxy,
    ))

    _display_results(report)
    return report