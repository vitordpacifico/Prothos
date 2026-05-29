import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

GRAPHQL_PATHS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query",
                 "/graphql/console", "/api/gql", "/gql", "/graphql/v1", "/playground"]

INTROSPECTION_QUERY = {"query": "{__schema{queryType{name} types{name kind}}}"}
SUGGESTION_QUERY = {"query": "{__typename nme}"}
SIMPLE_QUERY = {"query": "{__typename}"}

SEVERITY_COLOR = {
    "critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "cyan",
}


@dataclass
class GraphQLFinding:
    kind:       str
    endpoint:   str
    detail:     str
    severity:   str          = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class GraphQLReport:
    target:      str
    started_at:  str                     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]          = None
    endpoints:   list[str]              = field(default_factory=list)
    findings:    list[GraphQLFinding]   = field(default_factory=list)
    errors:      list[str]              = field(default_factory=list)

    @property
    def high(self) -> list[GraphQLFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _add(report, kind, endpoint, detail, severity):
    f = GraphQLFinding(kind=kind, endpoint=endpoint, detail=detail, severity=severity)
    report.findings.append(f)
    _print_finding(f)


async def _probe(client, url) -> bool:
    try:
        r = await client.post(url, json=SIMPLE_QUERY, timeout=10)
        if r.status_code < 500:
            body = r.text.lower()
            if "__typename" in body or "\"data\"" in body or "\"errors\"" in body or "graphql" in body:
                return True
    except Exception:
        pass
    return False


async def _analyze(client, url, report):
    try:
        r = await client.post(url, json=INTROSPECTION_QUERY, timeout=12)
        body = r.text
        if "\"__schema\"" in body or "\"queryType\"" in body:
            _add(report, "Introspection enabled", url,
                 "Full schema is queryable via __schema introspection", "high")
    except Exception as e:
        report.errors.append(f"introspection: {str(e)[:80]}")

    try:
        r = await client.post(url, json=SUGGESTION_QUERY, timeout=10)
        if "did you mean" in r.text.lower():
            _add(report, "Field suggestions", url,
                 "Server returns 'Did you mean' suggestions (schema inference)", "medium")
    except Exception:
        pass

    try:
        r = await client.get(url, params={"query": "{__typename}"}, timeout=10)
        if r.status_code < 400 and ("__typename" in r.text or "\"data\"" in r.text):
            _add(report, "GET method allowed", url,
                 "Queries accepted over GET (CSRF / cache exposure risk)", "medium")
    except Exception:
        pass

    try:
        batch = [SIMPLE_QUERY, SIMPLE_QUERY, SIMPLE_QUERY]
        r = await client.post(url, json=batch, timeout=10)
        if r.text.strip().startswith("[") and r.text.count("__typename") >= 2:
            _add(report, "Query batching", url,
                 "Array batching accepted (brute-force / rate-limit bypass surface)", "medium")
    except Exception:
        pass


def _print_finding(f: GraphQLFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.kind}[/bold white] → [yellow]{f.detail}[/yellow] [dim]{f.endpoint}[/dim]"
    )


def _display(report: GraphQLReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]endpoints:[/dim] {len(report.endpoints)}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]GraphQL Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.endpoints:
        console.print("[dim]    No GraphQL endpoint found.[/dim]\n")
        return
    console.print(f"[dim]    Endpoints: {', '.join(report.endpoints)}[/dim]")

    if not report.findings:
        console.print("[dim]    No GraphQL issues found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Kind",     style="cyan", width=22)
    table.add_column("Detail",   style="yellow", min_width=35)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.kind, f.detail[:50])

    console.print(table)
    console.print()


async def _graphql_async(target, concurrency, proxy) -> GraphQLReport:
    report = GraphQLReport(target=target)
    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [target] + [urljoin(root, p) for p in GRAPHQL_PATHS]
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)",
                 "Content-Type": "application/json"},
    ) as client:
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as progress:
            progress.add_task("Scanning GraphQL...", total=None)

            async def _find(url):
                async with sem:
                    if await _probe(client, url):
                        return url
                    return None

            results = await asyncio.gather(*[_find(u) for u in dict.fromkeys(candidates)])
            report.endpoints = [u for u in results if u]

            for url in report.endpoints:
                await _analyze(client, url, report)

    report.findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_graphql_scan(
    target:      str,
    concurrency: int            = 10,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> GraphQLReport:

    console.print(f"\n[bold red][*][/bold red] GraphQL Scan → [bold white]{target}[/bold white]")

    report = asyncio.run(_graphql_async(target, concurrency, proxy))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
