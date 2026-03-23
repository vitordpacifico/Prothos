import asyncio
import json
import struct
import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@dataclass
class FaviconResult:
    url:          str
    hash_mmh3:    Optional[int]   = None
    hash_md5:     Optional[str]   = None
    hash_sha256:  Optional[str]   = None
    size:         int             = 0
    content_type: Optional[str]   = None
    shodan_query: Optional[str]   = None
    censys_query: Optional[str]   = None
    fofa_query:   Optional[str]   = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class FaviconReport:
    target:      str
    started_at:  str                    = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]         = None
    results:     list[FaviconResult]   = field(default_factory=list)
    errors:      list[str]            = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["results"] = [r.to_dict() for r in self.results]
        return d


FAVICON_PATHS = [
    "/favicon.ico",
    "/favicon.png",
    "/favicon.gif",
    "/favicon.svg",
    "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
    "/assets/favicon.ico",
    "/static/favicon.ico",
    "/images/favicon.ico",
    "/img/favicon.ico",
    "/public/favicon.ico",
    "/media/favicon.ico",
]


def _mmh3(data: bytes) -> int:
    b64  = base64.encodebytes(data)
    seed = 0
    key  = b64

    length = len(key)
    nblocks = length // 4

    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    for block_start in range(0, nblocks * 4, 4):
        k1 = (
            key[block_start + 3] << 24
            | key[block_start + 2] << 16
            | key[block_start + 1] << 8
            | key[block_start + 0]
        )

        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFF

        h1 ^= k1
        h1  = (h1 << 13 | h1 >> 19) & 0xFFFFFFFF
        h1  = (5 * h1 + 0xe6546b64) & 0xFFFFFFFF

    tail_index = nblocks * 4
    k1         = 0
    tail_size  = length & 3

    if tail_size >= 3:
        k1 ^= key[tail_index + 2] << 16
    if tail_size >= 2:
        k1 ^= key[tail_index + 1] << 8
    if tail_size >= 1:
        k1 ^= key[tail_index + 0]
        k1  = (c1 * k1) & 0xFFFFFFFF
        k1  = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
        k1  = (c2 * k1) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1  = (0x85ebca6b * h1) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1  = (0xc2b2ae35 * h1) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    return struct.unpack("i", struct.pack("I", h1))[0]


def _build_queries(hash_mmh3: int) -> tuple[str, str, str]:
    shodan  = f'http.favicon.hash:{hash_mmh3}'
    censys  = f'services.http.response.favicons.md5_hash="{hash_mmh3}"'
    fofa    = f'icon_hash="{hash_mmh3}"'
    return shodan, censys, fofa


async def _probe(
    client: httpx.AsyncClient,
    url:    str,
    sem:    asyncio.Semaphore,
) -> Optional[FaviconResult]:

    async with sem:
        try:
            r = await client.get(url, timeout=10)

            if r.status_code != 200:
                return None

            content = r.content
            if not content or len(content) < 10:
                return None

            ct = r.headers.get("content-type", "")

            if not any(t in ct for t in (
                "image", "icon", "octet-stream", "x-icon",
            )) and not url.endswith((".ico", ".png", ".gif", ".svg")):
                if len(content) > 50000:
                    return None

            hash_mmh3  = _mmh3(content)
            hash_md5   = hashlib.md5(content).hexdigest()
            hash_sha256 = hashlib.sha256(content).hexdigest()

            shodan, censys, fofa = _build_queries(hash_mmh3)

            return FaviconResult(
                url=url,
                hash_mmh3=hash_mmh3,
                hash_md5=hash_md5,
                hash_sha256=hash_sha256,
                size=len(content),
                content_type=ct[:60],
                shodan_query=shodan,
                censys_query=censys,
                fofa_query=fofa,
            )

        except Exception:
            return None


async def _probe_html_favicon(
    client: httpx.AsyncClient,
    base:   str,
    sem:    asyncio.Semaphore,
) -> list[str]:
    import re
    extra = []
    try:
        r = await client.get(base, timeout=10)
        matches = re.findall(
            r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
            r.text,
            re.IGNORECASE,
        )
        matches += re.findall(
            r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut )?icon["\']',
            r.text,
            re.IGNORECASE,
        )
        for href in matches:
            if href.startswith("http"):
                extra.append(href)
            else:
                extra.append(urljoin(base, href))
    except Exception:
        pass
    return extra


def _display(report: FaviconReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]favicons found:[/dim] [green]{len(report.results)}[/green]",
        title="[bold red]Favicon Hash — Summary[/bold red]",
        border_style="red",
    ))

    if not report.results:
        console.print("[dim]    No favicons found.[/dim]\n")
        return

    for r in report.results:
        console.print(f"\n[cyan]{r.url}[/cyan]")
        console.print(f"  [dim]Size:[/dim]         {r.size}b")
        console.print(f"  [dim]Content-Type:[/dim] {r.content_type or '-'}")
        console.print(f"  [dim]MurmurHash3:[/dim]  [bold yellow]{r.hash_mmh3}[/bold yellow]")
        console.print(f"  [dim]MD5:[/dim]          {r.hash_md5}")
        console.print(f"  [dim]SHA256:[/dim]       {r.hash_sha256[:40]}...")
        console.print()
        console.print(f"  [dim]Shodan:[/dim]   [bold]{r.shodan_query}[/bold]")
        console.print(f"  [dim]Censys:[/dim]   {r.censys_query}")
        console.print(f"  [dim]FOFA:[/dim]     {r.fofa_query}")

    console.print()


async def _favicon_async(
    target:      str,
    concurrency: int,
) -> FaviconReport:

    report = FaviconReport(target=target)
    sem    = asyncio.Semaphore(concurrency)
    base   = target.rstrip("/")

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        console.print(f"[dim]    Extracting favicon URLs from HTML...[/dim]")
        html_favicons = await _probe_html_favicon(client, base, sem)
        if html_favicons:
            console.print(f"[dim]    Found {len(html_favicons)} favicon(s) in HTML[/dim]")

        urls = list(set(
            [base + path for path in FAVICON_PATHS] + html_favicons
        ))

        console.print(f"[dim]    Probing {len(urls)} URLs...[/dim]")

        tasks   = [_probe(client, url, sem) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen_hashes = set()
        for result in results:
            if isinstance(result, FaviconResult):
                if result.hash_mmh3 not in seen_hashes:
                    seen_hashes.add(result.hash_mmh3)
                    report.results.append(result)
                    console.print(
                        f"  [green][+][/green] {result.url} "
                        f"[dim]hash: {result.hash_mmh3}[/dim]"
                    )

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_favicon_hash(
    target:      str,
    concurrency: int          = 10,
    save_json:   Optional[str]= None,
) -> FaviconReport:

    console.print(
        f"\n[bold red][*][/bold red] Favicon Hash → "
        f"[bold white]{target}[/bold white]"
    )

    report = asyncio.run(_favicon_async(
        target=target,
        concurrency=concurrency,
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