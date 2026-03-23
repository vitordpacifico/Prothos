import asyncio
import json
import re
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
class WaybackResult:
    url:        str
    timestamp:  str
    status:     Optional[int]  = None
    mime:       Optional[str]  = None
    length:     Optional[int]  = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class WaybackReport:
    target:       str
    started_at:   str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:  Optional[str]            = None
    total:        int                       = 0
    urls:         list[WaybackResult]       = field(default_factory=list)
    interesting:  list[WaybackResult]       = field(default_factory=list)
    params:       list[str]                = field(default_factory=list)
    extensions:   dict[str, int]           = field(default_factory=dict)
    errors:       list[str]               = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["urls"]        = [r.to_dict() for r in self.urls]
        d["interesting"] = [r.to_dict() for r in self.interesting]
        return d


INTERESTING_EXTENSIONS = {
    "php", "asp", "aspx", "jsp", "cgi", "pl", "py", "rb",
    "env", "config", "conf", "cfg", "ini", "yaml", "yml",
    "json", "xml", "sql", "bak", "backup", "old", "orig",
    "log", "txt", "csv", "xls", "xlsx", "pdf",
    "zip", "tar", "gz", "rar", "7z",
    "pem", "key", "cert", "crt", "p12", "pfx",
}

INTERESTING_PATHS = {
    "admin", "administrator", "backup", "config", "debug",
    "internal", "private", "secret", "test", "dev", "staging",
    "api", "graphql", "swagger", "actuator", "metrics",
    ".env", ".git", ".svn", "phpinfo", "console", "dashboard",
}

INTERESTING_PARAMS = {
    "id", "user", "uid", "admin", "debug", "token", "key",
    "secret", "password", "cmd", "exec", "file", "path",
    "url", "redirect", "return", "next", "goto", "target",
    "query", "q", "search", "sql", "inject",
}


def _extract_params(url: str) -> list[str]:
    parsed = urlparse(url)
    if not parsed.query:
        return []
    return [p.split("=")[0] for p in parsed.query.split("&") if p]


def _get_extension(url: str) -> Optional[str]:
    path = urlparse(url).path
    if "." in path.split("/")[-1]:
        return path.split(".")[-1].lower()
    return None


def _is_interesting(result: WaybackResult) -> bool:
    url   = result.url.lower()
    path  = urlparse(url).path.lower()
    ext   = _get_extension(url)

    if ext and ext in INTERESTING_EXTENSIONS:
        return True

    if any(p in path for p in INTERESTING_PATHS):
        return True

    params = _extract_params(url)
    if any(p.lower() in INTERESTING_PARAMS for p in params):
        return True

    if result.status in (301, 302, 307, 308):
        return True

    return False


async def _fetch_cdx(
    client: httpx.AsyncClient,
    domain: str,
    limit:  int,
) -> list[WaybackResult]:
    results = []
    try:
        params = {
            "url":        f"*.{domain}/*",
            "output":     "json",
            "fl":         "original,timestamp,statuscode,mimetype,length",
            "collapse":   "urlkey",
            "limit":      str(limit),
            "filter":     "statuscode:200|301|302|403|500",
        }
        r = await client.get(
            "https://web.archive.org/cdx/search/cdx",
            params=params,
            timeout=30,
        )
        if r.status_code != 200:
            return results

        lines = r.json()
        if not lines or len(lines) < 2:
            return results

        for row in lines[1:]:
            if len(row) < 5:
                continue
            url, ts, status, mime, length = row
            try:
                results.append(WaybackResult(
                    url=url,
                    timestamp=ts,
                    status=int(status) if status.isdigit() else None,
                    mime=mime,
                    length=int(length) if length.isdigit() else None,
                ))
            except Exception:
                pass

    except Exception as e:
        pass

    return results


async def _fetch_also(
    client: httpx.AsyncClient,
    domain: str,
) -> list[str]:
    extra = []
    try:
        r = await client.get(
            f"https://web.archive.org/cdx/search/cdx",
            params={
                "url":    f"{domain}/*",
                "output": "json",
                "fl":     "original",
                "collapse":"urlkey",
                "limit":  "500",
            },
            timeout=20,
        )
        if r.status_code == 200:
            rows = r.json()
            extra = [row[0] for row in rows[1:] if row]
    except Exception:
        pass
    return extra


def _analyze(report: WaybackReport):
    ext_count: dict[str, int] = {}

    for result in report.urls:
        ext = _get_extension(result.url)
        if ext:
            ext_count[ext] = ext_count.get(ext, 0) + 1

        params = _extract_params(result.url)
        for p in params:
            if p and p not in report.params:
                report.params.append(p)

        if _is_interesting(result):
            report.interesting.append(result)

    report.extensions = dict(
        sorted(ext_count.items(), key=lambda x: x[1], reverse=True)
    )


def _display(report: WaybackReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]urls:[/dim] {report.total}  "
        f"[dim]interesting:[/dim] [yellow]{len(report.interesting)}[/yellow]  "
        f"[dim]params:[/dim] {len(report.params)}",
        title="[bold red]Wayback Scraper — Summary[/bold red]",
        border_style="red",
    ))

    if report.extensions:
        console.print(f"\n[dim]Top extensions:[/dim]")
        for ext, count in list(report.extensions.items())[:10]:
            bar  = "█" * min(count, 30)
            flag = " [red][!][/red]" if ext in INTERESTING_EXTENSIONS else ""
            console.print(f"  [cyan].{ext}[/cyan]{flag}  {bar} {count}")

    if report.params:
        console.print(f"\n[dim]Discovered params ({len(report.params)}):[/dim]")
        interesting_params = [p for p in report.params if p.lower() in INTERESTING_PARAMS]
        other_params       = [p for p in report.params if p.lower() not in INTERESTING_PARAMS]

        for p in interesting_params[:20]:
            console.print(f"  [red]→[/red] [yellow]{p}[/yellow] [red][!][/red]")
        for p in other_params[:20]:
            console.print(f"  [dim]→ {p}[/dim]")
        if len(report.params) > 40:
            console.print(f"  [dim]... and {len(report.params) - 40} more[/dim]")

    if report.interesting:
        console.print(f"\n[bold red][!] Interesting URLs ({len(report.interesting)}):[/bold red]")
        table = Table(
            show_header=True,
            header_style="bold red",
            border_style="dim",
        )
        table.add_column("Status", width=8)
        table.add_column("URL",    min_width=60, style="cyan")
        table.add_column("Date",   width=12, style="dim")

        for r in report.interesting[:50]:
            color = "green" if r.status == 200 else "yellow" if r.status in (301, 302) else "red"
            date  = r.timestamp[:8] if r.timestamp else "-"
            table.add_row(
                f"[{color}]{r.status or '-'}[/{color}]",
                r.url[:80],
                date,
            )
        console.print(table)

        if len(report.interesting) > 50:
            console.print(f"[dim]    ... and {len(report.interesting) - 50} more[/dim]")

    console.print()


async def _wayback_async(
    domain: str,
    limit:  int,
) -> WaybackReport:

    report = WaybackReport(target=domain)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        console.print(f"[dim]    Querying Wayback CDX API (limit: {limit})...[/dim]")
        results = await _fetch_cdx(client, domain, limit)
        report.urls  = results
        report.total = len(results)

        console.print(f"[dim]    Found {report.total} archived URLs[/dim]")

        if report.total < limit // 2:
            console.print(f"[dim]    Fetching exact domain URLs...[/dim]")
            extra_urls = await _fetch_also(client, domain)
            seen       = {r.url for r in report.urls}
            for url in extra_urls:
                if url not in seen:
                    seen.add(url)
                    report.urls.append(WaybackResult(url=url, timestamp=""))
            report.total = len(report.urls)
            console.print(f"[dim]    Total after merge: {report.total}[/dim]")

    _analyze(report)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_wayback_scraper(
    target: str,
    limit:  int          = 5000,
    save_json: Optional[str] = None,
) -> WaybackReport:

    from urllib.parse import urlparse
    parsed = urlparse(target)
    domain = parsed.hostname or target

    console.print(
        f"\n[bold red][*][/bold red] Wayback Scraper → "
        f"[bold white]{domain}[/bold white]"
    )

    report = asyncio.run(_wayback_async(
        domain=domain,
        limit=limit,
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