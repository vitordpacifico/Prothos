import asyncio
import json
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

@dataclass
class PortResult:
    port:          int
    protocol:      str                = "tcp"
    state:         str                = "open"
    service:       Optional[str]      = None
    banner:        Optional[str]      = None
    response_time: float              = 0.0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class PortScanReport:
    target:        str
    ip:            str                        = ""
    started_at:    str                        = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:   Optional[str]             = None
    total_tested:  int                        = 0
    open_ports:    list[PortResult]           = field(default_factory=list)
    filtered:      list[int]                  = field(default_factory=list)
    errors:        list[str]                  = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["open_ports"] = [p.to_dict() for p in self.open_ports]
        return d

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111,
    119, 135, 139, 143, 161, 194, 389, 443, 445,
    465, 500, 512, 513, 514, 587, 631, 636, 993,
    995, 1080, 1194, 1433, 1521, 1723, 2049, 2121,
    2222, 2375, 2376, 3000, 3001, 3128, 3306, 3389,
    3690, 4000, 4443, 4444, 4848, 5000, 5001, 5432,
    5601, 5672, 5900, 5984, 6000, 6379, 6443, 7000,
    7001, 7077, 7443, 7474, 8000, 8001, 8008, 8009,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
    8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095,
    8096, 8097, 8098, 8099, 8100, 8180, 8181, 8243,
    8333, 8443, 8444, 8500, 8800, 8880, 8983, 9000,
    9001, 9002, 9090, 9091, 9092, 9093, 9200, 9300,
    9418, 9443, 9999, 10000, 10250, 10255, 11211,
    15672, 16010, 27017, 27018, 28017, 50000, 50070,
    61616,
]

SERVICE_MAP = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    80:    "http",
    81:    "http-alt",
    88:    "kerberos",
    110:   "pop3",
    111:   "rpcbind",
    119:   "nntp",
    135:   "msrpc",
    139:   "netbios",
    143:   "imap",
    161:   "snmp",
    389:   "ldap",
    443:   "https",
    445:   "smb",
    465:   "smtps",
    587:   "smtp-submission",
    636:   "ldaps",
    993:   "imaps",
    995:   "pop3s",
    1080:  "socks",
    1433:  "mssql",
    1521:  "oracle",
    1723:  "pptp",
    2049:  "nfs",
    2375:  "docker",
    2376:  "docker-tls",
    3000:  "http-dev",
    3306:  "mysql",
    3389:  "rdp",
    3690:  "svn",
    4444:  "metasploit",
    5000:  "http-dev",
    5432:  "postgresql",
    5601:  "kibana",
    5672:  "rabbitmq",
    5900:  "vnc",
    5984:  "couchdb",
    6379:  "redis",
    7001:  "weblogic",
    7474:  "neo4j",
    8080:  "http-proxy",
    8443:  "https-alt",
    8500:  "consul",
    8983:  "solr",
    9000:  "sonarqube",
    9090:  "prometheus",
    9092:  "kafka",
    9200:  "elasticsearch",
    9300:  "elasticsearch-transport",
    10250: "kubelet",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    27018: "mongodb",
    28017: "mongodb-web",
    50070: "hadoop",
    61616: "activemq",
}

BANNER_PORTS = {21, 22, 23, 25, 80, 110, 143, 443, 8080, 8443}

async def _tcp_connect(
    host: str,
    port: int,
    timeout: float,
) -> tuple[bool, float, Optional[str]]:
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        elapsed = round(time.perf_counter() - t0, 3)

        banner = None
        if port in BANNER_PORTS:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                banner = data.decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return True, elapsed, banner

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        elapsed = round(time.perf_counter() - t0, 3)
        return False, elapsed, None


async def _scan_port(
    host:    str,
    port:    int,
    sem:     asyncio.Semaphore,
    timeout: float,
) -> Optional[PortResult]:

    async with sem:
        open_, elapsed, banner = await _tcp_connect(host, port, timeout)

        if not open_:
            return None

        return PortResult(
            port=port,
            protocol="tcp",
            state="open",
            service=SERVICE_MAP.get(port),
            banner=banner,
            response_time=elapsed,
        )

INTERESTING_SERVICES = {
    "docker", "redis", "mongodb", "elasticsearch", "memcached",
    "rabbitmq", "rabbitmq-mgmt", "kafka", "consul", "kubelet",
    "metasploit", "vnc", "rdp", "telnet", "snmp",
    "couchdb", "neo4j", "solr", "sonarqube", "weblogic",
    "hadoop", "activemq", "postgresql", "mysql", "mssql",
    "oracle", "nfs", "rpcbind", "netbios", "smb",
}


def _display(report: PortScanReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]ip:[/dim] {report.ip}  "
        f"[dim]tested:[/dim] {report.total_tested}  "
        f"[dim]open:[/dim] [green]{len(report.open_ports)}[/green]",
        title="[bold red]Port Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.open_ports:
        console.print("[dim]    No open ports found.[/dim]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold red",
        border_style="dim",
    )
    table.add_column("Port",     width=8)
    table.add_column("Proto",    width=6, style="dim")
    table.add_column("Service",  width=20, style="cyan")
    table.add_column("Time",     width=7, style="dim")
    table.add_column("Banner",   min_width=30, style="dim italic")

    interesting_found = []

    for r in sorted(report.open_ports, key=lambda x: x.port):
        flag = ""
        if r.service in INTERESTING_SERVICES:
            flag = " [red][!][/red]"
            interesting_found.append(r)

        table.add_row(
            f"[green]{r.port}[/green]",
            r.protocol,
            (r.service or "unknown") + flag,
            f"{r.response_time}s",
            (r.banner or "-")[:60],
        )

    console.print(table)

    if interesting_found:
        console.print(f"\n[bold red][!] Exposed sensitive services:[/bold red]")
        for r in interesting_found:
            console.print(
                f"    [red]→[/red] [green]{r.port}[/green]/tcp "
                f"[cyan]{r.service}[/cyan]"
                + (f" — {r.banner[:60]}" if r.banner else "")
            )

    console.print()

async def _scan_async(
    host:        str,
    ports:       list[int],
    concurrency: int,
    timeout:     float,
) -> PortScanReport:

    report              = PortScanReport(target=host)
    report.total_tested = len(ports)
    sem                 = asyncio.Semaphore(concurrency)

    try:
        report.ip = socket.gethostbyname(host)
    except Exception:
        report.ip = host

    tasks = [_scan_port(host, port, sem, timeout) for port in ports]

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
        task_id = progress.add_task(
            f"Scanning {report.ip}",
            total=len(tasks),
        )
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                report.open_ports.append(result)
                console.print(
                    f"  [green]{result.port}[/green]/tcp "
                    f"[cyan]{result.service or 'unknown'}[/cyan]"
                    + (f" [dim]{result.banner[:60]}[/dim]" if result.banner else "")
                )
            progress.advance(task_id)

    report.open_ports.sort(key=lambda x: x.port)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_port_scan(
    target:      str,
    ports:       Optional[list[int]] = None,
    preset:      str                 = "common",
    concurrency: int                 = 300,
    timeout:     float               = 1.5,
    save_json:   Optional[str]       = None,
) -> PortScanReport:
    
    from urllib.parse import urlparse
    parsed = urlparse(target)
    host   = parsed.hostname or target

    console.print(f"\n[bold red][*][/bold red] Port Scan → [bold white]{host}[/bold white]")

    if ports:
        port_list = ports
    elif preset == "full":
        port_list = list(range(1, 65536))
    elif preset == "web":
        port_list = [
            80, 81, 443, 800, 888, 1080, 3000, 4000, 4443,
            5000, 7000, 7443, 8000, 8001, 8008, 8080, 8081,
            8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
            8090, 8180, 8243, 8443, 8444, 8800, 8880, 9000,
            9001, 9090, 9443, 10000,
        ]
    elif preset == "db":
        port_list = [
            1433, 1521, 2483, 2484, 3306, 5432, 5984,
            6379, 7474, 9200, 9300, 11211, 27017, 27018,
            28017, 50000,
        ]
    else:
        port_list = COMMON_PORTS

    console.print(
        f"[dim]    Ports: {len(port_list)}  "
        f"Concurrency: {concurrency}  "
        f"Timeout: {timeout}s[/dim]"
    )

    report = asyncio.run(_scan_async(
        host=host,
        ports=port_list,
        concurrency=concurrency,
        timeout=timeout,
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