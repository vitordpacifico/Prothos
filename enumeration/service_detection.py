import asyncio
import json
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class ServiceResult:
    host:          str
    port:          int
    protocol:      str               = "tcp"
    service:       Optional[str]     = None
    version:       Optional[str]     = None
    banner:        Optional[str]     = None
    fingerprint:   Optional[str]     = None
    response_time: float             = 0.0
    interesting:   bool              = False
    notes:         list[str]         = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ServiceReport:
    target:      str
    started_at:  str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None
    results:     list[ServiceResult]      = field(default_factory=list)
    errors:      list[str]               = field(default_factory=list)

    @property
    def interesting(self) -> list[ServiceResult]:
        return [r for r in self.results if r.interesting]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["results"] = [r.to_dict() for r in self.results]
        return d


PROBES = {
    "http": b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "ftp":  b"",
    "ssh":  b"",
    "smtp": b"EHLO prothos\r\n",
    "pop3": b"",
    "imap": b"",
    "raw":  b"\r\n",
}

FINGERPRINTS = [
    (r"SSH-(\d+\.\d+)-OpenSSH_([\d.]+\w*)",      "ssh",        "OpenSSH {2}"),
    (r"SSH-(\d+\.\d+)-",                          "ssh",        "SSH"),
    (r"220.*FTP|FTP.*220",                         "ftp",        "FTP"),
    (r"220.*vsftpd\s*([\d.]+)",                    "ftp",        "vsftpd {1}"),
    (r"220.*ProFTPD\s*([\d.]+)",                   "ftp",        "ProFTPD {1}"),
    (r"220.*FileZilla",                            "ftp",        "FileZilla FTP"),
    (r"220.*smtp|ESMTP",                           "smtp",       "SMTP"),
    (r"220.*Postfix",                              "smtp",       "Postfix"),
    (r"220.*Exim\s*([\d.]+)",                      "smtp",       "Exim {1}"),
    (r"220.*Sendmail",                             "smtp",       "Sendmail"),
    (r"\+OK.*POP3",                                "pop3",       "POP3"),
    (r"\+OK.*Dovecot",                             "pop3",       "Dovecot POP3"),
    (r"\* OK.*IMAP",                               "imap",       "IMAP"),
    (r"\* OK.*Dovecot",                            "imap",       "Dovecot IMAP"),
    (r"HTTP/[\d.]+ \d+",                           "http",       "HTTP"),
    (r"Server: Apache/([\d.]+)",                   "http",       "Apache {1}"),
    (r"Server: nginx/([\d.]+)",                    "http",       "nginx {1}"),
    (r"Server: Microsoft-IIS/([\d.]+)",            "http",       "IIS {1}"),
    (r"Server: lighttpd/([\d.]+)",                 "http",       "lighttpd {1}"),
    (r"Server: Jetty\(([\d.]+)\)",                 "http",       "Jetty {1}"),
    (r"Server: gunicorn",                          "http",       "gunicorn"),
    (r"Server: Werkzeug",                          "http",       "Werkzeug/Flask"),
    (r"Server: Cowboy",                            "http",       "Cowboy/Elixir"),
    (r"Server: Kestrel",                           "http",       "Kestrel/.NET"),
    (r"-ERR.*Redis|NOAUTH|WRONGTYPE",              "redis",      "Redis"),
    (r"\*\d+\r\n|\+PONG",                         "redis",      "Redis"),
    (r"mongodb",                                   "mongodb",    "MongoDB"),
    (r"MySQL|mysql_native_password",               "mysql",      "MySQL"),
    (r"PostgreSQL|pg_hba",                         "postgresql", "PostgreSQL"),
    (r"AMQP|RabbitMQ",                             "rabbitmq",   "RabbitMQ"),
    (r"Elasticsearch",                             "elasticsearch", "Elasticsearch"),
    (r"memcache",                                  "memcached",  "Memcached"),
    (r"STAT pid",                                  "memcached",  "Memcached"),
]

INTERESTING_SERVICES = {
    "redis", "mongodb", "elasticsearch", "memcached", "rabbitmq",
    "mysql", "postgresql", "ftp", "telnet", "vnc", "rdp",
    "docker", "kafka", "cassandra", "couchdb",
}

HTTP_PORTS = {80, 81, 443, 800, 888, 3000, 4000, 4443, 5000, 7000,
              7443, 8000, 8001, 8008, 8080, 8081, 8082, 8083, 8084,
              8085, 8086, 8087, 8088, 8089, 8090, 8180, 8243, 8443,
              8444, 8800, 8880, 9000, 9001, 9090, 9200, 9443, 10000}


def _fingerprint(banner: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    for pattern, service, version_tpl in FINGERPRINTS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            try:
                version = version_tpl.format(*[""] + list(m.groups()))
            except Exception:
                version = version_tpl
            return service, version.strip(), banner[:200]
    return None, None, banner[:200]


async def _grab_banner_tcp(
    host:    str,
    port:    int,
    timeout: float,
) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        banner = None
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=2)
            banner = data.decode("utf-8", errors="replace").strip()
        except Exception:
            pass

        if not banner:
            if port in HTTP_PORTS:
                probe = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            else:
                probe = b"\r\n"
            writer.write(probe)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(2048), timeout=2)
                banner = data.decode("utf-8", errors="replace").strip()
            except Exception:
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return banner

    except Exception:
        return None


async def _grab_http(
    host:   str,
    port:   int,
    timeout: float,
) -> Optional[str]:
    scheme = "https" if port in {443, 8443, 4443, 7443, 9443} else "http"
    url    = f"{scheme}://{host}:{port}/"
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            r = await client.get(url)
            headers = dict(r.headers)
            parts   = []
            for h in ("server", "x-powered-by", "x-generator", "via"):
                if h in headers:
                    parts.append(f"{h}: {headers[h]}")
            parts.append(f"status: {r.status_code}")
            return " | ".join(parts) if parts else f"HTTP {r.status_code}"
    except Exception:
        return None


async def _detect(
    host:    str,
    port:    int,
    sem:     asyncio.Semaphore,
    timeout: float,
) -> ServiceResult:

    result = ServiceResult(host=host, port=port)

    async with sem:
        t0 = time.perf_counter()

        if port in HTTP_PORTS:
            banner = await _grab_http(host, port, timeout)
        else:
            banner = await _grab_banner_tcp(host, port, timeout)

        result.response_time = round(time.perf_counter() - t0, 3)

        if banner:
            result.banner = banner[:300]
            service, version, fp = _fingerprint(banner)
            result.service     = service
            result.version     = version
            result.fingerprint = fp

            if service in INTERESTING_SERVICES:
                result.interesting = True
                result.notes.append(f"Exposed {service}")

            if port == 6379 and not service:
                result.service     = "redis"
                result.interesting = True
            if port == 27017 and not service:
                result.service     = "mongodb"
                result.interesting = True
            if port == 9200 and not service:
                result.service     = "elasticsearch"
                result.interesting = True
            if port == 11211 and not service:
                result.service     = "memcached"
                result.interesting = True

        if not result.service:
            from enumeration.port_scan import SERVICE_MAP
            result.service = SERVICE_MAP.get(port)

        return result


def _display(report: ServiceReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]detected:[/dim] {len(report.results)}  "
        f"[dim]interesting:[/dim] [red]{len(report.interesting)}[/red]",
        title="[bold red]Service Detection — Summary[/bold red]",
        border_style="red",
    ))

    if not report.results:
        console.print("[dim]    No services detected.[/dim]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold red",
        border_style="dim",
    )
    table.add_column("Port",     width=7)
    table.add_column("Service",  width=16, style="cyan")
    table.add_column("Version",  width=25, style="white")
    table.add_column("Time",     width=7,  style="dim")
    table.add_column("Banner",   min_width=35, style="dim italic")

    for r in sorted(report.results, key=lambda x: x.port):
        flag = " [red][!][/red]" if r.interesting else ""
        table.add_row(
            f"[green]{r.port}[/green]",
            (r.service or "unknown") + flag,
            r.version or "-",
            f"{r.response_time}s",
            (r.banner or "-")[:60],
        )

    console.print(table)

    if report.interesting:
        console.print(f"\n[bold red][!] Exposed sensitive services:[/bold red]")
        for r in report.interesting:
            console.print(
                f"    [red]→[/red] [green]{r.port}[/green]/tcp "
                f"[cyan]{r.service}[/cyan]"
                + (f" {r.version}" if r.version else "")
                + (f" — {r.banner[:60]}" if r.banner else "")
            )

    console.print()


async def _detect_async(
    host:        str,
    ports:       list[int],
    concurrency: int,
    timeout:     float,
) -> ServiceReport:

    report = ServiceReport(target=host)
    sem    = asyncio.Semaphore(concurrency)
    tasks  = [_detect(host, port, sem, timeout) for port in ports]

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
        task_id = progress.add_task("Detecting services", total=len(tasks))
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result.banner:
                report.results.append(result)
                flag = " [red][!][/red]" if result.interesting else ""
                console.print(
                    f"  [green]{result.port}[/green]/tcp "
                    f"[cyan]{result.service or 'unknown'}[/cyan]{flag}"
                    + (f" {result.version}" if result.version else "")
                )
            progress.advance(task_id)

    report.results.sort(key=lambda x: x.port)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_service_detection(
    target:      str,
    ports:       Optional[list[int]] = None,
    concurrency: int                 = 50,
    timeout:     float               = 3.0,
    save_json:   Optional[str]       = None,
) -> ServiceReport:

    from urllib.parse import urlparse
    parsed = urlparse(target)
    host   = parsed.hostname or target

    console.print(
        f"\n[bold red][*][/bold red] Service Detection → "
        f"[bold white]{host}[/bold white]"
    )

    if not ports:
        from enumeration.port_scan import COMMON_PORTS
        ports = COMMON_PORTS

    console.print(
        f"[dim]    Ports: {len(ports)}  "
        f"Concurrency: {concurrency}  "
        f"Timeout: {timeout}s[/dim]"
    )

    report = asyncio.run(_detect_async(
        host=host,
        ports=ports,
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