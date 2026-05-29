import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()


@dataclass
class MSFModuleInfo:
    name:       str
    fullname:   str
    rank:       str          = ""
    disclosure: str          = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class MSFReport:
    host:        str
    port:        int
    started_at:  str                    = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]         = None
    connected:   bool                  = False
    version:     dict                  = field(default_factory=dict)
    modules:     list[MSFModuleInfo]   = field(default_factory=list)
    job_id:      Optional[int]         = None
    console_output: str                = ""
    errors:      list[str]             = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["modules"] = [m.to_dict() for m in self.modules]
        return d


class _MsfRpc:
    def __init__(self, client, base, ssl):
        self.client = client
        self.scheme = "https" if ssl else "http"
        self.base = base
        self.token = None

    async def call(self, method: str, *args) -> Any:
        import msgpack
        payload = [method, self.token, *args] if self.token else [method, *args]
        body = msgpack.packb(payload, use_bin_type=True)
        r = await self.client.post(
            f"{self.scheme}://{self.base}/api/",
            content=body,
            headers={"Content-Type": "binary/message-pack"},
            timeout=30,
        )
        return msgpack.unpackb(r.content, raw=False)

    async def login(self, user: str, password: str) -> bool:
        res = await self.call("auth.login", user, password)
        if isinstance(res, dict) and res.get("result") == "success":
            self.token = res.get("token")
            return True
        return False


def _display(report: MSFReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.host}:{report.port}[/bold white]  "
        f"[dim]connected:[/dim] {'yes' if report.connected else 'no'}  "
        f"[dim]version:[/dim] {report.version.get('version', '-')}  "
        f"[dim]modules:[/dim] [yellow]{len(report.modules)}[/yellow]"
        + (f"  [dim]job:[/dim] {report.job_id}" if report.job_id else ""),
        title="[bold red]Metasploit Bridge — Summary[/bold red]",
        border_style="red",
    ))

    if report.modules:
        table = Table(show_header=True, header_style="bold red", border_style="dim")
        table.add_column("Module", style="bold white", min_width=40)
        table.add_column("Rank",   style="cyan", width=12)
        for m in report.modules[:40]:
            table.add_row(m.fullname, m.rank)
        console.print(table)
        if len(report.modules) > 40:
            console.print(f"[dim]    ... and {len(report.modules) - 40} more[/dim]")

    if report.console_output:
        console.print(f"\n[dim]console output:[/dim]\n{report.console_output[:1500]}")
    console.print()


async def _bridge_async(host, port, user, password, ssl, module_type,
                        search, module, options, run) -> MSFReport:
    report = MSFReport(host=host, port=port)

    try:
        import msgpack  # noqa: F401
    except ImportError:
        report.errors.append("msgpack not installed — run: pip install msgpack")
        console.print("[red][!] msgpack missing[/red]")
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report

    async with httpx.AsyncClient(verify=False) as client:
        rpc = _MsfRpc(client, f"{host}:{port}", ssl)

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Talking to msfrpcd...", total=None)
            try:
                if not await rpc.login(user, password):
                    report.errors.append("auth.login failed")
                    console.print("[red][!] Login failed — check msfrpcd creds/host[/red]")
                    report.finished_at = datetime.now(timezone.utc).isoformat()
                    return report
                report.connected = True

                try:
                    ver = await rpc.call("core.version")
                    if isinstance(ver, dict):
                        report.version = {k: str(v) for k, v in ver.items()}
                except Exception:
                    pass

                listing = await rpc.call(f"module.{module_type}")
                names = listing.get("modules", []) if isinstance(listing, dict) else []
                for full in names:
                    if search and search.lower() not in full.lower():
                        continue
                    report.modules.append(MSFModuleInfo(name=full.split("/")[-1], fullname=full))
                console.print(f"[dim]    {len(report.modules)} {module_type} module(s) listed[/dim]")

                if module and run:
                    opts = options or {}
                    res = await rpc.call("module.execute", module_type.rstrip("s"), module, opts)
                    if isinstance(res, dict):
                        report.job_id = res.get("job_id")
                        console.print(f"[yellow]    [>] module.execute job_id={report.job_id}[/yellow]")
                elif module:
                    info = await rpc.call("module.info", module_type.rstrip("s"), module)
                    if isinstance(info, dict):
                        report.console_output = json.dumps(info, default=str)[:1500]

            except Exception as e:
                report.errors.append(str(e)[:200])

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_metasploit_bridge(
    host:        str,
    port:        int                 = 55553,
    user:        str                 = "msf",
    password:    str                 = "",
    ssl:         bool                = True,
    module_type: str                 = "exploits",
    search:      Optional[str]       = None,
    module:      Optional[str]       = None,
    options:     Optional[dict]      = None,
    run:         bool                = False,
    proxy:       Optional[str]       = None,
    save_json:   Optional[str]       = None,
) -> MSFReport:

    console.print(f"\n[bold red][*][/bold red] Metasploit Bridge → [bold white]{host}:{port}[/bold white]")
    console.print(f"[dim]    type={module_type} search={search or '-'} "
                  f"module={module or '-'} run={run}[/dim]")

    report = asyncio.run(_bridge_async(host, port, user, password, ssl, module_type,
                                       search, module, options, run))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
