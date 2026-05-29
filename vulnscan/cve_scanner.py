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
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

CVE_DB: dict[str, list[dict]] = {
    "apache": [
        {"cve": "CVE-2021-41773", "cvss": 7.5, "exact": ["2.4.49"],
         "desc": "Path traversal and RCE in mod_cgi (2.4.49)"},
        {"cve": "CVE-2021-42013", "cvss": 9.8, "exact": ["2.4.49", "2.4.50"],
         "desc": "Path traversal/RCE incomplete fix of 41773"},
        {"cve": "CVE-2021-44790", "cvss": 9.8, "lt": "2.4.52",
         "desc": "Buffer overflow in mod_lua multipart parser"},
        {"cve": "CVE-2017-15715", "cvss": 8.1, "lt": "2.4.30",
         "desc": "<FilesMatch> newline bypass allowing upload of malicious files"},
        {"cve": "CVE-2019-0211", "cvss": 7.8, "ge": "2.4.17", "lt": "2.4.39",
         "desc": "Local privilege escalation via scoreboard (MPM event/worker/prefork)"},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "cvss": 8.1, "lt": "1.21.0",
         "desc": "Off-by-one in resolver leading to potential RCE"},
        {"cve": "CVE-2019-20372", "cvss": 5.3, "lt": "1.17.7",
         "desc": "Error_page request smuggling / open redirect"},
        {"cve": "CVE-2013-2028", "cvss": 7.5, "ge": "1.3.9", "lt": "1.5.0",
         "desc": "Stack buffer overflow in chunked transfer-encoding"},
    ],
    "iis": [
        {"cve": "CVE-2015-1635", "cvss": 9.8, "exact": ["10.0", "8.5", "8.0", "7.5"],
         "desc": "HTTP.sys remote code execution (MS15-034)"},
        {"cve": "CVE-2017-7269", "cvss": 9.8, "exact": ["6.0"],
         "desc": "WebDAV ScStoragePathFromUrl buffer overflow RCE"},
    ],
    "php": [
        {"cve": "CVE-2019-11043", "cvss": 9.8, "lt": "7.3.11",
         "desc": "php-fpm + nginx remote code execution"},
        {"cve": "CVE-2012-1823", "cvss": 7.5, "lt": "5.3.12",
         "desc": "php-cgi query string argument injection RCE"},
    ],
    "openssl": [
        {"cve": "CVE-2014-0160", "cvss": 7.5, "ge": "1.0.1", "lt": "1.0.1g",
         "desc": "Heartbleed information disclosure"},
        {"cve": "CVE-2022-3602", "cvss": 7.5, "ge": "3.0.0", "lt": "3.0.7",
         "desc": "X.509 punycode buffer overflow"},
    ],
    "jquery": [
        {"cve": "CVE-2020-11022", "cvss": 6.1, "ge": "1.2.0", "lt": "3.5.0",
         "desc": "XSS via passing HTML from untrusted sources to DOM manipulation methods"},
        {"cve": "CVE-2020-11023", "cvss": 6.1, "ge": "1.0.3", "lt": "3.5.0",
         "desc": "XSS via <option> elements from untrusted HTML"},
        {"cve": "CVE-2019-11358", "cvss": 6.1, "lt": "3.4.0",
         "desc": "Prototype pollution via $.extend"},
        {"cve": "CVE-2015-9251", "cvss": 6.1, "lt": "3.0.0",
         "desc": "XSS via cross-domain ajax with text/javascript response"},
    ],
    "bootstrap": [
        {"cve": "CVE-2019-8331", "cvss": 6.1, "lt": "3.4.1",
         "desc": "XSS in tooltip/popover data-template"},
        {"cve": "CVE-2018-14041", "cvss": 6.1, "lt": "3.4.0",
         "desc": "XSS in data-target via scrollspy"},
        {"cve": "CVE-2018-14042", "cvss": 6.1, "lt": "3.4.0",
         "desc": "XSS in data-container via tooltip"},
    ],
    "angular": [
        {"cve": "CVE-2020-7676", "cvss": 6.1, "lt": "1.8.0",
         "desc": "AngularJS XSS via xlink:href"},
        {"cve": "CVE-2019-10768", "cvss": 7.5, "lt": "1.7.9",
         "desc": "AngularJS prototype pollution in merge"},
    ],
    "tomcat": [
        {"cve": "CVE-2020-1938", "cvss": 9.8, "ge": "6.0.0", "lt": "9.0.31",
         "desc": "Ghostcat AJP file read/inclusion leading to RCE"},
        {"cve": "CVE-2017-12617", "cvss": 8.1, "lt": "9.0.1",
         "desc": "JSP upload RCE via PUT when readonly=false"},
    ],
    "spring": [
        {"cve": "CVE-2022-22965", "cvss": 9.8, "lt": "5.3.18",
         "desc": "Spring4Shell RCE via data binding on JDK 9+"},
    ],
    "wordpress": [
        {"cve": "CVE-2022-21661", "cvss": 8.0, "lt": "5.8.3",
         "desc": "WP_Query SQL injection"},
    ],
    "openssh": [
        {"cve": "CVE-2024-6387", "cvss": 8.1, "ge": "8.5", "lt": "9.8",
         "desc": "regreSSHion: signal handler race condition RCE"},
    ],
}

SERVER_PRODUCTS: dict[str, str] = {
    "apache": "apache", "nginx": "nginx", "microsoft-iis": "iis", "iis": "iis",
    "openssl": "openssl", "php": "php", "tomcat": "tomcat", "coyote": "tomcat",
    "openssh": "openssh",
}

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class DetectedTech:
    product:    str
    version:    str
    source:     str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class CVEFinding:
    product:    str
    version:    str
    cve:        str
    cvss:       float
    description: str
    severity:   str          = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class CVEReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    detected:    list[DetectedTech]  = field(default_factory=list)
    findings:    list[CVEFinding]    = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def critical(self) -> list[CVEFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> list[CVEFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["detected"] = [t.to_dict() for t in self.detected]
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _vt(version: str) -> tuple:
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts[:4]) or (0,)


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _is_affected(version: str, entry: dict) -> bool:
    v = _vt(version)
    if "exact" in entry:
        return version in entry["exact"] or any(_vt(e) == v for e in entry["exact"])
    if "ge" in entry and v < _vt(entry["ge"]):
        return False
    if "lt" in entry and not (v < _vt(entry["lt"])):
        return False
    return "lt" in entry or "ge" in entry


def _detect_from_headers(headers: dict) -> list[DetectedTech]:
    detected = []
    blob = " ".join(f"{k}: {v}" for k, v in headers.items())
    for m in re.finditer(r"([A-Za-z][\w\-]+)/(\d+(?:\.\d+){1,3})", blob):
        name = m.group(1).lower()
        version = m.group(2)
        product = SERVER_PRODUCTS.get(name)
        if product:
            detected.append(DetectedTech(product=product, version=version, source="header"))
    powered = headers.get("x-powered-by", "")
    pm = re.search(r"PHP/(\d+(?:\.\d+){1,3})", powered, re.IGNORECASE)
    if pm:
        detected.append(DetectedTech(product="php", version=pm.group(1), source="x-powered-by"))
    return detected


def _detect_from_body(body: str) -> list[DetectedTech]:
    detected = []
    lib_patterns = {
        "jquery": [r"jquery[/-](\d+\.\d+\.\d+)", r"jQuery\s+v(\d+\.\d+\.\d+)", r"jQuery JavaScript Library v(\d+\.\d+\.\d+)"],
        "bootstrap": [r"bootstrap[/-](\d+\.\d+\.\d+)", r"Bootstrap\s+v(\d+\.\d+\.\d+)"],
        "angular": [r"angular[.\-/](\d+\.\d+\.\d+)", r"ng-version=[\"'](\d+\.\d+\.\d+)", r"AngularJS\s+v(\d+\.\d+\.\d+)"],
    }
    for product, patterns in lib_patterns.items():
        for pat in patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                detected.append(DetectedTech(product=product, version=m.group(1), source="body"))
                break
    gm = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)', body, re.IGNORECASE)
    if gm:
        detected.append(DetectedTech(product="wordpress", version=gm.group(1), source="generator"))
    return detected


def _match_cves(tech: DetectedTech) -> list[CVEFinding]:
    findings = []
    for entry in CVE_DB.get(tech.product, []):
        if _is_affected(tech.version, entry):
            findings.append(CVEFinding(
                product=tech.product, version=tech.version,
                cve=entry["cve"], cvss=entry["cvss"], description=entry["desc"],
                severity=_cvss_to_severity(entry["cvss"]),
            ))
    return findings


async def _query_nvd(client, product: str, version: str) -> list[CVEFinding]:
    findings = []
    try:
        r = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": f"{product} {version}", "resultsPerPage": 20},
            timeout=20,
        )
        if r.status_code != 200:
            return findings
        data = r.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            cvss = 0.0
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            if cve_id:
                findings.append(CVEFinding(
                    product=product, version=version, cve=cve_id, cvss=cvss,
                    description=desc[:160], severity=_cvss_to_severity(cvss),
                ))
    except Exception:
        pass
    return findings


def _print_finding(f: CVEFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.product} {f.version}[/bold white] → "
        f"[red]{f.cve}[/red] [dim](CVSS {f.cvss})[/dim] "
        f"[yellow]{f.description[:55]}[/yellow]"
    )


def _display(report: CVEReport):
    console.print()
    techs = ", ".join(f"{t.product}/{t.version}" for t in report.detected) or "none"
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]\n"
        f"[dim]detected:[/dim] {techs}\n"
        f"[dim]CVEs:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]CVE Scanner — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No known CVEs matched detected versions.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Product",   style="cyan", width=14)
    table.add_column("Version",   style="dim", width=10)
    table.add_column("CVE",       style="bold white", width=16)
    table.add_column("CVSS",      style="magenta", width=6)
    table.add_column("Description", style="yellow", min_width=30)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.product, f.version, f.cve, str(f.cvss), f.description[:55],
        )

    console.print(table)
    console.print()


async def _cve_async(target, use_nvd, proxy) -> CVEReport:
    report = CVEReport(target=target)

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
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Mapping CVEs...", total=None)

            try:
                r = await client.get(target, timeout=15)
                headers = {k.lower(): v for k, v in r.headers.items()}
                report.detected.extend(_detect_from_headers(headers))
                report.detected.extend(_detect_from_body(r.text))
            except Exception as e:
                report.errors.append(f"fetch failed: {e}")

            seen = set()
            unique = []
            for t in report.detected:
                key = (t.product, t.version)
                if key not in seen:
                    seen.add(key)
                    unique.append(t)
            report.detected = unique

            for tech in report.detected:
                local = _match_cves(tech)
                for f in local:
                    report.findings.append(f)
                    _print_finding(f)
                if use_nvd:
                    nvd = await _query_nvd(client, tech.product, tech.version)
                    known = {f.cve for f in report.findings}
                    for f in nvd:
                        if f.cve not in known:
                            report.findings.append(f)
                            _print_finding(f)

            progress.update(task_id, completed=1, total=1)

    report.findings.sort(key=lambda x: -x.cvss)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_cve_scanner(
    target:        str,
    use_nvd:       bool           = False,
    proxy:         Optional[str]  = None,
    save_json:     Optional[str]  = None,
) -> CVEReport:

    console.print(f"\n[bold red][*][/bold red] CVE Scanner → [bold white]{target}[/bold white]")
    console.print(f"[dim]    Local DB products: {len(CVE_DB)}  NVD lookup: {'on' if use_nvd else 'off'}[/dim]")

    report = asyncio.run(_cve_async(
        target=target,
        use_nvd=use_nvd,
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
