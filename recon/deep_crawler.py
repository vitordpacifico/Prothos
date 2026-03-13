import asyncio
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

RE_API_STRING = re.compile(
    r'["\'](\/?(?:api|v\d|graphql|rest|internal|admin|auth|rpc)'
    r'[a-zA-Z0-9/_\-\.:%@!~,;=?&#+]*)["\']'
)

RE_PARAMS = re.compile(r'[?&]([a-zA-Z0-9_\-]+)=')

RE_COMMENTS = re.compile(r'<!--(.*?)-->', re.DOTALL)

RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

RE_SECRETS = [
    (re.compile(r'(?:api[_-]?key|token|secret|password)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "Secret"),
    (re.compile(r'AKIA[0-9A-Z]{16}'),                                                              "AWS Key"),
    (re.compile(r'AIza[0-9A-Za-z_\-]{35}'),                                                       "Google Key"),
    (re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),                                          "Private Key"),
]

IGNORE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".pdf", ".zip", ".gz", ".tar",
    ".map", ".min.js",
}

INTERESTING_FORM_METHODS = {"post", "put", "patch", "delete"}

@dataclass
class CrawledPage:
    url:          str
    status:       int
    depth:        int
    title:        Optional[str]   = None
    content_type: Optional[str]   = None
    content_len:  Optional[int]   = None
    response_time:Optional[float] = None
    links:        list[str]       = field(default_factory=list)
    api_endpoints:list[str]       = field(default_factory=list)
    forms:        list[dict]      = field(default_factory=list)
    params:       list[str]       = field(default_factory=list)
    comments:     list[str]       = field(default_factory=list)
    emails:       list[str]       = field(default_factory=list)
    secrets:      list[str]       = field(default_factory=list)
    interesting:  bool            = False
    notes:        list[str]       = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class DeepCrawlReport:
    target:        str
    started_at:    str            = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:   Optional[str] = None
    max_depth:     int            = 3
    pages_crawled: list[CrawledPage]  = field(default_factory=list)
    all_urls:      list[str]          = field(default_factory=list)
    all_apis:      list[str]          = field(default_factory=list)
    all_params:    list[str]          = field(default_factory=list)
    all_forms:     list[dict]         = field(default_factory=list)
    all_emails:    list[str]          = field(default_factory=list)
    all_secrets:   list[str]          = field(default_factory=list)
    all_comments:  list[str]          = field(default_factory=list)
    errors:        list[str]          = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["pages_crawled"] = [p.to_dict() for p in self.pages_crawled]
        return d

def _is_same_domain(url: str, target: str) -> bool:
    target_host = urlparse(target).netloc.lower().lstrip("www.")
    url_host    = urlparse(url).netloc.lower().lstrip("www.")
    return url_host == target_host or url_host.endswith("." + target_host)


def _should_ignore(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in IGNORE_EXTENSIONS)


def _normalize_url(url: str) -> str:
    """Remove fragmentos e normaliza trailing slash."""
    p = urlparse(url)
    return p._replace(fragment="").geturl()


def _extract_forms(soup: BeautifulSoup, base_url: str) -> list[dict]:
    """Extrai todos os forms com seus campos, métodos e actions."""
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urljoin(base_url, action) if action else base_url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inp_name = inp.get("name") or inp.get("id", "")
            inp_type = inp.get("type", "text")
            if inp_name:
                inputs.append({"name": inp_name, "type": inp_type})

        forms.append({
            "action":      action_url,
            "method":      method,
            "inputs":      inputs,
            "interesting": method in INTERESTING_FORM_METHODS or any(
                kw in action_url.lower()
                for kw in ["login", "auth", "upload", "admin", "search", "api"]
            ),
        })
    return forms


def _analyze_page(
    url:     str,
    status:  int,
    headers: dict,
    body:    str,
    soup:    BeautifulSoup,
) -> tuple[bool, list[str]]:
    """Retorna (interesting, notes) para a página."""
    notes       = []
    interesting = False
    path        = urlparse(url).path.lower()

    if status in {401, 403}:
        notes.append(" Auth required")
        interesting = True
    elif status in {500, 502, 503}:
        notes.append(" Server error")
        interesting = True

    body_lower = body[:5000].lower()

    if re.search(r"traceback|stack.?trace|exception", body_lower):
        notes.append(" Stack trace")
        interesting = True
    if re.search(r"index of /|directory listing", body_lower):
        notes.append(" Dir listing")
        interesting = True
    if re.search(r"\"debug\"\s*:\s*true", body_lower):
        notes.append(" Debug mode")
        interesting = True
    if re.search(r"swagger|openapi|api.?doc", body_lower):
        notes.append(" API docs")
        interesting = True
    if re.search(r"graphql|__schema", body_lower):
        notes.append(" GraphQL")
        interesting = True
    if headers.get("x-powered-by"):
        notes.append(f"Powered-By: {headers['x-powered-by']}")

    return interesting, notes

async def _fetch_page(
    client:  httpx.AsyncClient,
    url:     str,
    depth:   int,
    target:  str,
    sem:     asyncio.Semaphore,
) -> Optional[CrawledPage]:

    async with sem:
        try:
            t0 = time.perf_counter()
            r  = await client.get(url, timeout=12)
            elapsed = round(time.perf_counter() - t0, 3)

            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            content_type  = headers_lower.get("content-type", "")

            if not any(ct in content_type for ct in ("html", "javascript", "json", "text")):
                return None

            body = r.text
            soup = BeautifulSoup(body, "lxml") if "html" in content_type else None

            title = None
            if soup:
                t = soup.find("title")
                title = t.get_text(strip=True)[:80] if t else None

            links = []
            if soup:
                for tag in soup.find_all("a", href=True):
                    href = tag["href"].strip()
                    if href and not href.startswith(("mailto:", "tel:", "javascript:")):
                        full = _normalize_url(urljoin(url, href))
                        if _is_same_domain(full, target) and not _should_ignore(full):
                            links.append(full)

                for tag in soup.find_all(["script", "iframe"], src=True):
                    src  = tag.get("src", "").strip()
                    if src:
                        full = _normalize_url(urljoin(url, src))
                        if _is_same_domain(full, target):
                            links.append(full)

            api_endpoints = list({
                urljoin(url, ep) if ep.startswith("/") else ep
                for ep in RE_API_STRING.findall(body)
            })

            forms = _extract_forms(soup, url) if soup else []

            params = list(set(RE_PARAMS.findall(body)))

            raw_comments = RE_COMMENTS.findall(body)
            comments = [c.strip()[:200] for c in raw_comments
                        if len(c.strip()) > 10 and not c.strip().startswith("[if")]

            emails = list(set(RE_EMAIL.findall(body)))

            secrets = []
            for pattern, kind in RE_SECRETS:
                for m in pattern.finditer(body):
                    val = m.group(0)[:60]
                    secrets.append(f"[{kind}] {val}")

            interesting, notes = _analyze_page(url, r.status_code, headers_lower, body, soup)

            if secrets:
                notes.append(f"🔑 {len(secrets)} secret(s)")
                interesting = True
            if forms:
                interesting_forms = [f for f in forms if f["interesting"]]
                if interesting_forms:
                    notes.append(f"📝 {len(interesting_forms)} interesting form(s)")
                    interesting = True
            if comments:
                notes.append(f"💬 {len(comments)} comment(s)")

            return CrawledPage(
                url=url,
                status=r.status_code,
                depth=depth,
                title=title,
                content_type=content_type[:60],
                content_len=int(headers_lower.get("content-length", 0) or len(r.content)),
                response_time=elapsed,
                links=list(set(links)),
                api_endpoints=api_endpoints,
                forms=forms,
                params=params,
                comments=comments,
                emails=emails,
                secrets=secrets,
                interesting=interesting,
                notes=notes,
            )

        except httpx.TimeoutException:
            return None
        except Exception:
            return None


async def _crawl_async(
    target:      str,
    max_depth:   int,
    concurrency: int,
    max_pages:   int,
    proxy:       Optional[str],
) -> DeepCrawlReport:

    report    = DeepCrawlReport(target=target, max_depth=max_depth)
    visited   = set()
    proxies   = {"http://": proxy, "https://": proxy} if proxy else None
    sem       = asyncio.Semaphore(concurrency)

    queue: deque[tuple[str, int]] = deque([(target, 0)])

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        proxy=proxy,
    ) as client:

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Deep crawling...", total=None)

            while queue and len(visited) < max_pages:
                batch = []
                current_depth = queue[0][1] if queue else 0

                while queue and queue[0][1] == current_depth and len(batch) < concurrency:
                    url, depth = queue.popleft()
                    norm = _normalize_url(url)
                    if norm not in visited and not _should_ignore(norm):
                        visited.add(norm)
                        batch.append((url, depth))

                if not batch:
                    if queue:
                        url, depth = queue.popleft()
                        norm = _normalize_url(url)
                        if norm not in visited:
                            visited.add(norm)
                            batch.append((url, depth))
                    continue

                progress.update(
                    task_id,
                    description=f"[dim]depth {current_depth}[/dim]  "
                                f"[green]{len(report.pages_crawled)} crawled[/green]  "
                                f"[dim]queue: {len(queue)}[/dim]  "
                                f"[bold white]{urlparse(target).netloc}[/bold white]"
                )

                tasks   = [_fetch_page(client, url, depth, target, sem) for url, depth in batch]
                results = await asyncio.gather(*tasks)

                for page in results:
                    if not page:
                        continue

                    report.pages_crawled.append(page)
                    _print_page(page)

                    if page.depth < max_depth:
                        for link in page.links:
                            norm = _normalize_url(link)
                            if norm not in visited:
                                queue.append((link, page.depth + 1))

    all_urls    = set()
    all_apis    = set()
    all_params  = set()
    all_emails  = set()
    all_secrets = []
    all_forms   = []
    all_comments= []

    for page in report.pages_crawled:
        all_urls.add(page.url)
        all_urls.update(page.links)
        all_apis.update(page.api_endpoints)
        all_params.update(page.params)
        all_emails.update(page.emails)
        all_secrets.extend(page.secrets)
        all_forms.extend(page.forms)
        all_comments.extend(page.comments)

    report.all_urls     = sorted(all_urls)
    report.all_apis     = sorted(all_apis)
    report.all_params   = sorted(all_params)
    report.all_emails   = sorted(all_emails)
    report.all_secrets  = list(set(all_secrets))
    report.all_forms    = all_forms
    report.all_comments = all_comments
    report.finished_at  = datetime.now(timezone.utc).isoformat()
    return report

def _status_color(s: int) -> str:
    if s < 300: return "green"
    if s < 400: return "yellow"
    if s < 500: return "cyan"
    return "red"


def _print_page(p: CrawledPage):
    if not p.interesting and p.status == 200:
        return
    color  = _status_color(p.status)
    depth  = f"[dim]d{p.depth}[/dim]"
    flag   = " [bold red]★[/bold red]" if p.interesting else ""
    title  = f" [dim italic]{p.title}[/dim italic]" if p.title else ""
    notes  = f" [yellow]{' | '.join(p.notes[:2])}[/yellow]" if p.notes else ""
    console.print(f"  [{color}]{p.status}[/{color}] {depth} [white]{p.url}[/white]{title}{notes}{flag}")


def _display_summary(report: DeepCrawlReport):
    interesting = [p for p in report.pages_crawled if p.interesting]

    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]\n"
        f"[dim]pages:[/dim] [white]{len(report.pages_crawled)}[/white]  "
        f"[dim]urls:[/dim] [white]{len(report.all_urls)}[/white]  "
        f"[dim]apis:[/dim] [cyan]{len(report.all_apis)}[/cyan]  "
        f"[dim]params:[/dim] [white]{len(report.all_params)}[/white]  "
        f"[dim]forms:[/dim] [white]{len(report.all_forms)}[/white]  "
        f"[dim]emails:[/dim] [white]{len(report.all_emails)}[/white]  "
        f"[dim]secrets:[/dim] [{'red' if report.all_secrets else 'dim'}]{len(report.all_secrets)}[/{'red' if report.all_secrets else 'dim'}]  "
        f"[dim]interesting:[/dim] [yellow]{len(interesting)}[/yellow]",
        title="[bold red]Deep Crawler — Summary[/bold red]",
        border_style="red",
    ))

    if report.all_apis:
        console.print(f"\n[bold cyan]API Endpoints ({len(report.all_apis)})[/bold cyan]")
        for ep in sorted(report.all_apis)[:50]:
            console.print(f"  [cyan]→[/cyan] {ep}")
        if len(report.all_apis) > 50:
            console.print(f"  [dim]... and {len(report.all_apis) - 50} more[/dim]")

    if report.all_params:
        console.print(f"\n[bold white]URL Parameters ({len(report.all_params)})[/bold white]")
        console.print(f"  [dim]{', '.join(sorted(report.all_params))}[/dim]")

    interesting_forms = [f for f in report.all_forms if f.get("interesting")]
    if interesting_forms:
        console.print(f"\n[bold yellow]Interesting Forms ({len(interesting_forms)})[/bold yellow]")
        for f in interesting_forms[:10]:
            fields = ", ".join(i["name"] for i in f["inputs"][:5])
            console.print(f"  [yellow]{f['method'].upper()}[/yellow] {f['action']}  [dim]{fields}[/dim]")

    if report.all_emails:
        console.print(f"\n[bold white]Emails ({len(report.all_emails)})[/bold white]")
        for email in sorted(report.all_emails)[:20]:
            console.print(f"  [dim]@[/dim] {email}")

    if report.all_comments:
        console.print(f"\n[bold white]HTML Comments ({len(report.all_comments)})[/bold white]")
        for c in report.all_comments[:10]:
            short = c[:100].replace("\n", " ")
            console.print(f"  [dim]<!-- {short} -->[/dim]")

    if report.all_secrets:
        console.print(f"\n[bold red blink][!] SECRETS FOUND: {len(report.all_secrets)}[/bold red blink]")
        for s in report.all_secrets:
            console.print(f"  [red]→[/red] {s}")

    if interesting:
        console.print(f"\n[bold yellow]Interesting Pages ({len(interesting)})[/bold yellow]")
        table = Table(show_header=True, header_style="bold red", border_style="dim")
        table.add_column("Status", width=7)
        table.add_column("Depth",  width=6)
        table.add_column("URL",    min_width=40)
        table.add_column("Notes",  min_width=25)
        for p in interesting:
            c = _status_color(p.status)
            table.add_row(
                f"[{c}]{p.status}[/{c}]",
                str(p.depth),
                p.url,
                " | ".join(p.notes[:3]),
            )
        console.print(table)

    console.print()

def run_deep_crawler(
    target:      str,
    max_depth:   int           = 3,
    concurrency: int           = 15,
    max_pages:   int           = 500,
    proxy:       Optional[str] = None,
    save_json:   Optional[str] = None,
) -> DeepCrawlReport:

    console.print(f"\n[bold red][*][/bold red] Deep crawl → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Max depth: {max_depth}  Concurrency: {concurrency}  "
                  f"Max pages: {max_pages}[/dim]\n")

    report = asyncio.run(_crawl_async(
        target=target,
        max_depth=max_depth,
        concurrency=concurrency,
        max_pages=max_pages,
        proxy=proxy,
    ))

    _display_summary(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save JSON: {e}[/red]")

    return report