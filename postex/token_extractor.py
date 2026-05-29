import asyncio
import base64
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any
from urllib.parse import urlparse, urljoin
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
APIKEY_HEADER_RE = re.compile(r"(?i)^(x-api-key|api-key|x-auth-token|authorization)$")

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class ExtractedToken:
    kind:        str
    source:      str
    value:       str
    severity:    str          = "info"
    claims:      dict         = field(default_factory=dict)
    expired:     Optional[bool] = None
    note:        str          = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class TokenExtractReport:
    target:      str
    started_at:  str                       = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]            = None
    tokens:      list[ExtractedToken]     = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    @property
    def high(self) -> list[ExtractedToken]:
        return [t for t in self.tokens if t.severity in ("critical", "high")]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["tokens"] = [t.to_dict() for t in self.tokens]
        return d


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}, {}
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        header = {}
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        payload = {}
    return header, payload


def _redact(value: str) -> str:
    if len(value) <= 16:
        return value[:6] + "****"
    return value[:10] + "****" + value[-6:]


def _analyze_jwt(token: str, source: str, seen: set) -> Optional[ExtractedToken]:
    if token in seen:
        return None
    seen.add(token)
    header, payload = _decode_jwt(token)
    parts = token.split(".")

    expired = None
    note_bits = []
    severity = "medium"

    alg = str(header.get("alg", "")).lower()
    if alg == "none" or (len(parts) == 3 and parts[2] == ""):
        severity = "high"
        note_bits.append("alg=none / empty signature")

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        now = datetime.now(timezone.utc).timestamp()
        expired = exp < now
        note_bits.append("expired" if expired else "valid (not expired)")

    claims = {k: payload.get(k) for k in ("sub", "iss", "aud", "role", "roles", "scope", "admin", "email", "user") if k in payload}

    t = ExtractedToken(
        kind="JWT", source=source, value=_redact(token), severity=severity,
        claims=claims, expired=expired,
        note=("; ".join(note_bits) + f"; alg={header.get('alg', '?')}").strip("; "),
    )
    _print_token(t)
    return t


def _extract_from_headers(headers: dict, source: str, seen: set) -> list[ExtractedToken]:
    out = []
    for k, v in headers.items():
        if APIKEY_HEADER_RE.match(k):
            for m in JWT_RE.finditer(str(v)):
                jt = _analyze_jwt(m.group(0), f"{source} [header {k}]", seen)
                if jt:
                    out.append(jt)
            key = f"{k}:{v}"
            if not JWT_RE.search(str(v)) and key not in seen:
                seen.add(key)
                t = ExtractedToken(kind="API Key (header)", source=f"{source} [header {k}]",
                                   value=_redact(str(v)), severity="medium")
                _print_token(t)
                out.append(t)
    return out


def _extract_cookies(set_cookie: Any, source: str, seen: set) -> list[ExtractedToken]:
    out = []
    cookies = set_cookie if isinstance(set_cookie, list) else ([set_cookie] if set_cookie else [])
    for raw in cookies:
        first = str(raw).split(";")[0]
        if "=" not in first:
            continue
        name, value = first.split("=", 1)
        flags = str(raw).lower()
        missing = []
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "secure" not in flags:
            missing.append("Secure")
        if "samesite" not in flags:
            missing.append("SameSite")
        key = f"cookie:{name}:{source}"
        if key in seen:
            continue
        seen.add(key)
        severity = "medium" if missing else "low"
        t = ExtractedToken(
            kind="Session Cookie", source=source, value=f"{name}={_redact(value)}",
            severity=severity, note=("missing: " + ", ".join(missing)) if missing else "secure flags set",
        )
        _print_token(t)
        out.append(t)
        for m in JWT_RE.finditer(value):
            jt = _analyze_jwt(m.group(0), f"{source} [cookie {name}]", seen)
            if jt:
                out.append(jt)
    return out


def _print_token(t: ExtractedToken):
    color = SEVERITY_COLOR.get(t.severity, "white")
    console.print(
        f"  [{color}][{t.severity.upper()}][/{color}] "
        f"[bold white]{t.kind}[/bold white] → "
        f"[yellow]{t.value}[/yellow]  [dim]{t.note}[/dim]"
    )


def _display(report: TokenExtractReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]tokens:[/dim] [yellow]{len(report.tokens)}[/yellow]  "
        f"[dim]high+:[/dim] [red]{len(report.high)}[/red]",
        title="[bold red]Token Extractor — Summary[/bold red]",
        border_style="red",
    ))

    if not report.tokens:
        console.print("[dim]    No tokens extracted.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Severity",  width=10)
    table.add_column("Kind",      style="cyan", width=18)
    table.add_column("Value",     style="yellow", width=28)
    table.add_column("Note",      style="dim", min_width=22)

    for t in report.tokens:
        color = SEVERITY_COLOR.get(t.severity, "white")
        table.add_row(f"[{color}]{t.severity}[/{color}]", t.kind, t.value, t.note[:40])

    console.print(table)

    jwts = [t for t in report.tokens if t.kind == "JWT" and t.claims]
    if jwts:
        console.print("\n[dim]    JWT claims:[/dim]")
        for t in jwts:
            console.print(f"      [yellow]{t.value}[/yellow] → [dim]{t.claims}[/dim]")
    console.print()


async def _token_async(target, concurrency, proxy) -> TokenExtractReport:
    report = TokenExtractReport(target=target)
    seen: set = set()
    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"
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
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Extracting tokens...", total=None)

            async def _process(url):
                async with sem:
                    try:
                        r = await client.get(url, timeout=12)
                    except Exception:
                        return
                    hdrs = {k.lower(): v for k, v in r.headers.items()}
                    report.tokens.extend(_extract_from_headers(hdrs, url, seen))
                    set_cookie = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else r.headers.get("set-cookie")
                    report.tokens.extend(_extract_cookies(set_cookie, url, seen))
                    for m in JWT_RE.finditer(r.text):
                        jt = _analyze_jwt(m.group(0), url, seen)
                        if jt:
                            report.tokens.append(jt)

            urls = [target, urljoin(root, "/api/"), urljoin(root, "/login"), urljoin(root, "/auth")]
            tasks = [_process(u) for u in dict.fromkeys(urls)]
            await asyncio.gather(*tasks)

    report.tokens.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5)
    ))
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_token_extractor(
    target:      str,
    concurrency: int            = 8,
    proxy:       Optional[str]  = None,
    save_json:   Optional[str]  = None,
) -> TokenExtractReport:

    console.print(f"\n[bold red][*][/bold red] Token Extractor → [bold white]{target}[/bold white]")

    report = asyncio.run(_token_async(target=target, concurrency=concurrency, proxy=proxy))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
