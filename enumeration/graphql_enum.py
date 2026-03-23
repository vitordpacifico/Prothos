import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class GraphQLType:
    name:        str
    kind:        str
    fields:      list[str]  = field(default_factory=list)
    description: str        = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class GraphQLReport:
    target:           str
    started_at:       str                      = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:      Optional[str]           = None
    endpoints:        list[str]               = field(default_factory=list)
    introspection:    bool                    = False
    types:            list[GraphQLType]       = field(default_factory=list)
    queries:          list[str]               = field(default_factory=list)
    mutations:        list[str]               = field(default_factory=list)
    subscriptions:    list[str]               = field(default_factory=list)
    interesting:      list[str]               = field(default_factory=list)
    errors:           list[str]               = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["types"] = [t.to_dict() for t in self.types]
        return d


GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/",
    "/graphiql",
    "/graphiql/",
    "/api/graphql",
    "/api/graphiql",
    "/gql",
    "/query",
    "/playground",
    "/v1/graphql",
    "/v2/graphql",
    "/graph",
    "/graphql/v1",
    "/graphql/v2",
    "/graphql/console",
    "/graphql/explorer",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/graphql/playground",
    "/graphql/voyager",
]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
        args {
          name
          type {
            name
            kind
          }
        }
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
      }
    }
  }
}
"""

FIELD_SUGGESTION_QUERY = """
{ __typename }
"""

BATCH_QUERY = """
[
  {"query": "{ __typename }"},
  {"query": "{ __typename }"}
]
"""

INTERESTING_TYPES = {
    "user", "users", "admin", "password", "token", "secret",
    "key", "credential", "auth", "session", "role", "permission",
    "payment", "card", "credit", "billing", "order", "invoice",
    "config", "setting", "env", "debug", "internal", "private",
    "file", "upload", "download", "export", "import",
}

INTERESTING_FIELDS = {
    "password", "token", "secret", "key", "hash", "salt",
    "apikey", "api_key", "access_token", "refresh_token",
    "credit_card", "card_number", "cvv", "ssn", "dob",
    "phone", "address", "ip", "email", "role", "permission",
}


async def _probe_endpoint(
    client: httpx.AsyncClient,
    url:    str,
    sem:    asyncio.Semaphore,
) -> Optional[str]:
    async with sem:
        for method, kwargs in [
            ("POST", {"json": {"query": FIELD_SUGGESTION_QUERY}}),
            ("GET",  {"params": {"query": FIELD_SUGGESTION_QUERY}}),
        ]:
            try:
                if method == "POST":
                    r = await client.post(url, **kwargs, timeout=10)
                else:
                    r = await client.get(url, **kwargs, timeout=10)

                if r.status_code in (200, 400, 422):
                    body = r.text.lower()
                    if any(k in body for k in (
                        "__typename", "graphql", "errors", "data",
                        "did you mean", "cannot query"
                    )):
                        return url
            except Exception:
                pass
    return None


async def _run_introspection(
    client: httpx.AsyncClient,
    url:    str,
) -> Optional[dict]:
    for method, kwargs in [
        ("POST", {"json": {"query": INTROSPECTION_QUERY}}),
        ("GET",  {"params": {"query": INTROSPECTION_QUERY}}),
    ]:
        try:
            if method == "POST":
                r = await client.post(url, **kwargs, timeout=15)
            else:
                r = await client.get(url, **kwargs, timeout=15)

            if r.status_code == 200:
                data = r.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    return data["data"]["__schema"]
        except Exception:
            pass
    return None


async def _check_batching(
    client: httpx.AsyncClient,
    url:    str,
) -> bool:
    try:
        r = await client.post(
            url,
            content=BATCH_QUERY,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list) and len(data) > 1:
                return True
    except Exception:
        pass
    return False


async def _check_field_suggestions(
    client: httpx.AsyncClient,
    url:    str,
) -> bool:
    try:
        r = await client.post(
            url,
            json={"query": "{ nonExistentField }"},
            timeout=10,
        )
        body = r.text.lower()
        return "did you mean" in body or "suggestion" in body
    except Exception:
        return False


def _parse_schema(schema: dict) -> tuple[list[str], list[str], list[str], list[GraphQLType]]:
    queries       = []
    mutations     = []
    subscriptions = []
    types         = []

    all_types = schema.get("types", [])

    query_type_name = (schema.get("queryType") or {}).get("name", "Query")
    mut_type_name   = (schema.get("mutationType") or {}).get("name", "Mutation")
    sub_type_name   = (schema.get("subscriptionType") or {}).get("name", "Subscription")

    for t in all_types:
        name = t.get("name", "")
        kind = t.get("kind", "")

        if name.startswith("__"):
            continue

        fields = [
            f.get("name", "") for f in (t.get("fields") or [])
        ]

        if name == query_type_name:
            queries = fields
        elif name == mut_type_name:
            mutations = fields
        elif name == sub_type_name:
            subscriptions = fields
        elif kind in ("OBJECT", "INPUT_OBJECT", "INTERFACE"):
            types.append(GraphQLType(
                name=name,
                kind=kind,
                fields=fields,
                description=t.get("description") or "",
            ))

    return queries, mutations, subscriptions, types


def _find_interesting(
    queries:       list[str],
    mutations:     list[str],
    subscriptions: list[str],
    types:         list[GraphQLType],
) -> list[str]:
    findings = []

    for q in queries:
        if any(kw in q.lower() for kw in INTERESTING_TYPES):
            findings.append(f"Interesting query: {q}")

    for m in mutations:
        if any(kw in m.lower() for kw in INTERESTING_TYPES):
            findings.append(f"Interesting mutation: {m}")

    for t in types:
        if any(kw in t.name.lower() for kw in INTERESTING_TYPES):
            findings.append(f"Sensitive type: {t.name}")
        for f in t.fields:
            if any(kw in f.lower() for kw in INTERESTING_FIELDS):
                findings.append(f"Sensitive field: {t.name}.{f}")

    return findings


def _display(report: GraphQLReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]endpoints:[/dim] {len(report.endpoints)}  "
        f"[dim]introspection:[/dim] {'[red]OPEN[/red]' if report.introspection else '[dim]blocked[/dim]'}  "
        f"[dim]queries:[/dim] {len(report.queries)}  "
        f"[dim]mutations:[/dim] {len(report.mutations)}",
        title="[bold red]GraphQL Enum — Summary[/bold red]",
        border_style="red",
    ))

    if not report.endpoints:
        console.print("[dim]    No GraphQL endpoints found.[/dim]\n")
        return

    console.print(f"\n[dim]Endpoints found:[/dim]")
    for ep in report.endpoints:
        console.print(f"  [cyan]→ {ep}[/cyan]")

    if report.introspection:
        console.print(f"\n[bold red][!] Introspection is OPEN[/bold red]")

        if report.queries:
            console.print(f"\n[dim]Queries ({len(report.queries)}):[/dim]")
            for q in report.queries[:20]:
                console.print(f"  [green]→[/green] {q}")
            if len(report.queries) > 20:
                console.print(f"  [dim]... and {len(report.queries) - 20} more[/dim]")

        if report.mutations:
            console.print(f"\n[dim]Mutations ({len(report.mutations)}):[/dim]")
            for m in report.mutations[:20]:
                console.print(f"  [yellow]→[/yellow] {m}")
            if len(report.mutations) > 20:
                console.print(f"  [dim]... and {len(report.mutations) - 20} more[/dim]")

        if report.subscriptions:
            console.print(f"\n[dim]Subscriptions ({len(report.subscriptions)}):[/dim]")
            for s in report.subscriptions:
                console.print(f"  [cyan]→[/cyan] {s}")

        if report.types:
            table = Table(
                show_header=True,
                header_style="bold red",
                border_style="dim",
            )
            table.add_column("Type",   width=30, style="white")
            table.add_column("Kind",   width=15, style="dim")
            table.add_column("Fields", min_width=40, style="dim")

            for t in report.types[:30]:
                flag = " [red][!][/red]" if any(
                    kw in t.name.lower() for kw in INTERESTING_TYPES
                ) else ""
                table.add_row(
                    t.name + flag,
                    t.kind,
                    ", ".join(t.fields[:8]) + ("..." if len(t.fields) > 8 else ""),
                )
            console.print()
            console.print(table)

    if report.interesting:
        console.print(f"\n[bold red][!] Interesting findings:[/bold red]")
        for f in report.interesting:
            console.print(f"    [red]→[/red] {f}")

    console.print()


async def _graphql_async(
    target:      str,
    concurrency: int,
    proxy:       Optional[str],
) -> GraphQLReport:

    report = GraphQLReport(target=target)
    sem    = asyncio.Semaphore(concurrency)

    base = target.rstrip("/")

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        proxy=proxy,
        headers={
            "User-Agent":   "Mozilla/5.0 (compatible; Prothos/1.0)",
            "Content-Type": "application/json",
            "Accept":       "application/json",
        },
    ) as client:

        console.print(f"[dim]    Probing {len(GRAPHQL_PATHS)} paths...[/dim]")

        tasks = [
            _probe_endpoint(client, base + path, sem)
            for path in GRAPHQL_PATHS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, str):
                report.endpoints.append(result)
                console.print(f"  [green][+][/green] GraphQL endpoint: [cyan]{result}[/cyan]")

        if not report.endpoints:
            report.finished_at = datetime.now(timezone.utc).isoformat()
            return report

        primary = report.endpoints[0]

        console.print(f"[dim]    Running introspection on {primary}...[/dim]")
        schema = await _run_introspection(client, primary)

        if schema:
            report.introspection = True
            queries, mutations, subscriptions, types = _parse_schema(schema)
            report.queries       = queries
            report.mutations     = mutations
            report.subscriptions = subscriptions
            report.types         = types
            report.interesting   = _find_interesting(queries, mutations, subscriptions, types)
            console.print(f"[dim]    Schema: {len(queries)} queries, {len(mutations)} mutations, {len(types)} types[/dim]")
        else:
            console.print(f"[dim]    Introspection blocked[/dim]")

        console.print(f"[dim]    Checking query batching...[/dim]")
        if await _check_batching(client, primary):
            report.interesting.append("Query batching enabled — DoS/bruteforce risk")
            console.print(f"  [yellow][!][/yellow] Query batching is enabled")

        console.print(f"[dim]    Checking field suggestions...[/dim]")
        if await _check_field_suggestions(client, primary):
            report.interesting.append("Field suggestions enabled — schema leakage via error messages")
            console.print(f"  [yellow][!][/yellow] Field suggestions are enabled")

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_graphql_enum(
    target:      str,
    concurrency: int          = 10,
    proxy:       Optional[str]= None,
    save_json:   Optional[str]= None,
) -> GraphQLReport:

    console.print(
        f"\n[bold red][*][/bold red] GraphQL Enum → "
        f"[bold white]{target}[/bold white]"
    )

    report = asyncio.run(_graphql_async(
        target=target,
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