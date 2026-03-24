import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

@dataclass
class BucketResult:
    name:         str
    provider:     str
    url:          str
    status:       str                = "unknown"
    public:       bool               = False
    listable:     bool               = False
    writable:     bool               = False
    files:        list[str]          = field(default_factory=list)
    notes:        list[str]          = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()

@dataclass
class CloudEnumReport:
    target:       str
    started_at:   str                      = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:  Optional[str]           = None
    total_tested: int                      = 0
    found:        list[BucketResult]       = field(default_factory=list)
    errors:       list[str]               = field(default_factory=list)

    @property
    def public(self) -> list[BucketResult]:
        return [r for r in self.found if r.public]

    @property
    def listable(self) -> list[BucketResult]:
        return [r for r in self.found if r.listable]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["found"] = [r.to_dict() for r in self.found]
        return d

S3_URL        = "https://{bucket}.s3.amazonaws.com"
S3_ALT_URL    = "https://s3.amazonaws.com/{bucket}"
GCS_URL       = "https://storage.googleapis.com/{bucket}"
AZURE_URL     = "https://{bucket}.blob.core.windows.net"
DO_URL        = "https://{bucket}.digitaloceanspaces.com"
BACKBLAZE_URL = "https://{bucket}.s3.us-west-004.backblazeb2.com"
FIREBASE_URL  = "https://{bucket}.firebaseio.com/.json"
AZURE_STATIC  = "https://{bucket}.z13.web.core.windows.net"

def _build_names(domain: str) -> list[str]:
    base  = domain.split(".")[0]
    parts = domain.replace(".", "-")

    return list(set([
        base, parts, domain,
        f"{base}-backup", f"{base}-backups", f"{base}-bak",
        f"{base}-dev", f"{base}-staging", f"{base}-stage",
        f"{base}-prod", f"{base}-production",
        f"{base}-test", f"{base}-testing",
        f"{base}-static", f"{base}-assets", f"{base}-media",
        f"{base}-images", f"{base}-files", f"{base}-uploads",
        f"{base}-cdn", f"{base}-logs", f"{base}-data",
        f"{base}-archive", f"{base}-public", f"{base}-private",
        f"{base}-internal", f"{base}-admin", f"{base}-api",
        f"{base}-web", f"{base}-app", f"{base}-store",
        f"{base}-storage", f"{base}-bucket",
        f"{base}-s3", f"{base}-gcs", f"{base}-blob",
        f"www-{base}", f"api-{base}",
    ]))

async def _try_s3_bypasses(
    client: httpx.AsyncClient,
    url:    str,
    name:   str,
) -> list[str]:
    findings = []

    path_url = S3_ALT_URL.format(bucket=name)
    try:
        r = await client.get(path_url, timeout=5)
        if r.status_code == 200:
            findings.append("Path-style URL bypass works")
    except Exception:
        pass

    bypass_headers = [
        {"X-Forwarded-For":             "127.0.0.1"},
        {"X-Original-URL":              "/"},
        {"X-Rewrite-URL":               "/"},
        {"X-Custom-IP-Authorization":   "127.0.0.1"},
    ]
    for headers in bypass_headers:
        try:
            r = await client.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                findings.append(f"Header bypass: {list(headers.keys())[0]}")
                break
        except Exception:
            pass

    presigned_paths = ["/?list-type=2", "/?acl", "/?policy", "/?cors"]
    for path in presigned_paths:
        try:
            r = await client.get(url + path, timeout=5)
            if r.status_code == 200:
                findings.append(f"Exposed: {path}")
        except Exception:
            pass

    return findings

async def _check_s3_write(
    client: httpx.AsyncClient,
    url:    str,
    result: BucketResult,
):
    try:
        test_url = url.rstrip("/") + "/prothos-write-test.txt"
        r = await client.put(test_url, content=b"prothos", timeout=5)
        if r.status_code in (200, 201):
            result.writable = True
            result.notes.append("[!] WRITABLE — arbitrary file upload possible")
            await client.delete(test_url, timeout=5)
    except Exception:
        pass

async def _check_s3(
    client: httpx.AsyncClient,
    name:   str,
    sem:    asyncio.Semaphore,
) -> Optional[BucketResult]:

    url = S3_URL.format(bucket=name)

    async with sem:
        try:
            r = await client.get(url, timeout=8)

            if r.status_code == 404:
                return None

            result = BucketResult(name=name, provider="aws-s3", url=url)

            if r.status_code == 200:
                result.status = "exists"
                result.public = True
                if "<ListBucketResult" in r.text:
                    result.listable = True
                    result.notes.append("Bucket listing enabled")
                    keys = re.findall(r"<Key>([^<]+)</Key>", r.text)
                    result.files = keys[:20]

            elif r.status_code == 403:
                result.status = "exists"
                result.public = False
                result.notes.append("Exists but access denied")
                bypasses = await _try_s3_bypasses(client, url, name)
                if bypasses:
                    result.public = True
                    result.notes.extend(bypasses)

            elif r.status_code == 301:
                result.status = "exists"
                result.notes.append("Redirect — wrong region")

            else:
                return None

            await _check_s3_write(client, url, result)
            return result

        except Exception:
            return None

async def _check_gcs(
    client: httpx.AsyncClient,
    name:   str,
    sem:    asyncio.Semaphore,
) -> Optional[BucketResult]:

    url = GCS_URL.format(bucket=name)

    async with sem:
        try:
            r = await client.get(url, timeout=8)

            if r.status_code == 404:
                return None

            result = BucketResult(name=name, provider="gcp-gcs", url=url)

            if r.status_code == 200:
                result.status = "exists"
                result.public = True
                if "<ListBucketResult" in r.text or "<Contents>" in r.text:
                    result.listable = True
                    result.notes.append("Bucket listing enabled")
                    keys = re.findall(r"<Key>([^<]+)</Key>", r.text)
                    result.files = keys[:20]

            elif r.status_code == 403:
                result.status = "exists"
                result.public = False
                result.notes.append("Exists but access denied")
            else:
                return None

            return result

        except Exception:
            return None

async def _check_azure(
    client: httpx.AsyncClient,
    name:   str,
    sem:    asyncio.Semaphore,
) -> Optional[BucketResult]:

    url = AZURE_URL.format(bucket=name) + "?restype=container&comp=list"

    async with sem:
        try:
            r = await client.get(url, timeout=8)

            if r.status_code == 404:
                return None

            result = BucketResult(
                name=name,
                provider="azure-blob",
                url=AZURE_URL.format(bucket=name),
            )

            if r.status_code == 200:
                result.status   = "exists"
                result.public   = True
                result.listable = True
                result.notes.append("Container listing enabled")
                keys = re.findall(r"<Name>([^<]+)</Name>", r.text)
                result.files = keys[:20]

            elif r.status_code == 403:
                result.status = "exists"
                result.public = False
                result.notes.append("Exists but access denied")
            else:
                return None

            return result

        except Exception:
            return None

async def _check_firebase(
    client: httpx.AsyncClient,
    name:   str,
    sem:    asyncio.Semaphore,
) -> Optional[BucketResult]:

    url = FIREBASE_URL.format(bucket=name)

    async with sem:
        try:
            r = await client.get(url, timeout=8)

            if r.status_code == 404:
                return None

            result = BucketResult(name=name, provider="firebase", url=url)

            if r.status_code == 200:
                result.status = "exists"
                result.public = True
                if r.text and r.text != "null":
                    result.listable = True
                    result.notes.append("Firebase DB publicly readable")

            elif r.status_code in (401, 403):
                result.status = "exists"
                result.public = False
                result.notes.append("Exists but auth required")
            else:
                return None

            return result

        except Exception:
            return None

def _display(report: CloudEnumReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]tested:[/dim] {report.total_tested}  "
        f"[dim]found:[/dim] [green]{len(report.found)}[/green]  "
        f"[dim]public:[/dim] [red]{len(report.public)}[/red]  "
        f"[dim]listable:[/dim] [red]{len(report.listable)}[/red]",
        title="[bold red]Cloud Enum — Summary[/bold red]",
        border_style="red",
    ))

    if not report.found:
        console.print("[dim]    No cloud buckets found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Provider", width=12, style="dim")
    table.add_column("Bucket",   width=30, style="cyan")
    table.add_column("Status",   width=10)
    table.add_column("Public",   width=8)
    table.add_column("Listable", width=9)
    table.add_column("Writable", width=9)
    table.add_column("Notes",    min_width=25, style="yellow")

    for r in report.found:
        public   = "[red]YES[/red]" if r.public   else "[dim]no[/dim]"
        listable = "[red]YES[/red]" if r.listable else "[dim]no[/dim]"
        writable = "[red]YES[/red]" if r.writable else "[dim]no[/dim]"
        table.add_row(
            r.provider, r.name, r.status,
            public, listable, writable,
            " | ".join(r.notes[:2]) if r.notes else "-",
        )

    console.print(table)

    for r in report.listable:
        if r.files:
            console.print(f"\n[bold red][!] Files in {r.name} ({r.provider}):[/bold red]")
            for f in r.files[:10]:
                console.print(f"    [dim]→[/dim] {f}")
            if len(r.files) > 10:
                console.print(f"    [dim]... and {len(r.files) - 10} more[/dim]")

    console.print()

async def _cloud_async(
    target:      str,
    names:       list[str],
    concurrency: int,
) -> CloudEnumReport:

    report = CloudEnumReport(target=target)
    sem    = asyncio.Semaphore(concurrency)

    providers = ["S3", "GCS", "Azure", "Firebase"]
    report.total_tested = len(names) * len(providers)

    console.print(
        f"[dim]    Names: {len(names)}  "
        f"Providers: {', '.join(providers)}  "
        f"Total: {report.total_tested}[/dim]"
    )

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        tasks = []
        for name in names:
            tasks.append(_check_s3(client, name, sem))
            tasks.append(_check_gcs(client, name, sem))
            tasks.append(_check_azure(client, name, sem))
            tasks.append(_check_firebase(client, name, sem))

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
            task_id = progress.add_task("Enumerating cloud buckets", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    report.found.append(result)
                    flag = " [red][PUBLIC][/red]" if result.public else ""
                    console.print(
                        f"  [green][+][/green] [{result.provider}] "
                        f"[cyan]{result.name}[/cyan]{flag}"
                        + (f" — {result.notes[0]}" if result.notes else "")
                    )
                progress.advance(task_id)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report

def run_cloud_enum(
    target:      str,
    extra_names: Optional[list[str]] = None,
    concurrency: int                 = 30,
    save_json:   Optional[str]       = None,
) -> CloudEnumReport:

    from urllib.parse import urlparse
    parsed = urlparse(target)
    domain = parsed.hostname or target

    console.print(
        f"\n[bold red][*][/bold red] Cloud Enum → "
        f"[bold white]{domain}[/bold white]"
    )

    names = _build_names(domain)
    if extra_names:
        names = list(set(names + extra_names))

    report = asyncio.run(_cloud_async(
        target=target,
        names=names,
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