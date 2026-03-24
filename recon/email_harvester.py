import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, quote

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class EmailResult:
    email:      str
    source:     str
    confidence: str = "medium"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class EmailReport:
    target:      str
    domain:      str                    = ""
    started_at:  str                    = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]         = None
    emails:      list[EmailResult]     = field(default_factory=list)
    unique:      list[str]             = field(default_factory=list)
    patterns:    list[str]             = field(default_factory=list)
    errors:      list[str]            = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["emails"] = [e.to_dict() for e in self.emails]
        return d


EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com",
    "throwaway.email", "yopmail.com", "sharklasers.com",
}


def _is_valid_email(email: str, domain: str) -> bool:
    if len(email) > 254:
        return False
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return False
    local = email.split("@")[0]
    if any(c in local for c in (" ", "\n", "\t", "<", ">")):
        return False
    if email.split("@")[1].lower() in DISPOSABLE_DOMAINS:
        return False
    return True


def _extract_emails(text: str, domain: str, source: str) -> list[EmailResult]:
    found   = []
    matches = EMAIL_REGEX.findall(text)
    for email in set(matches):
        email = email.lower().strip(".,;:")
        if _is_valid_email(email, domain):
            found.append(EmailResult(
                email=email,
                source=source,
                confidence="high" if domain in email else "low",
            ))
    return found


async def _scrape_hunter(client: httpx.AsyncClient, domain: str) -> list[EmailResult]:
    try:
        r = await client.get(
            "https://hunter.io/try/v2/domain-search",
            params={"domain": domain, "limit": "10"},
            timeout=15,
        )
        return _extract_emails(r.text, domain, "hunter.io")
    except Exception:
        return []


async def _scrape_phonebook(client: httpx.AsyncClient, domain: str) -> list[EmailResult]:
    try:
        r = await client.post(
            "https://phonebook.cz/api/v1/search",
            json={"term": domain, "type": "email"},
            timeout=15,
        )
        return _extract_emails(r.text, domain, "phonebook.cz")
    except Exception:
        return []


async def _scrape_emailrep(client: httpx.AsyncClient, domain: str) -> list[EmailResult]:
    try:
        r = await client.get(f"https://emailrep.io/query/{domain}", timeout=10)
        return _extract_emails(r.text, domain, "emailrep.io")
    except Exception:
        return []


async def _scrape_google(client: httpx.AsyncClient, domain: str) -> list[EmailResult]:
    results = []
    for q in [f'site:{domain} "@{domain}"', f'"@{domain}" email', f'"{domain}" contact email']:
        try:
            r = await client.get(
                "https://www.google.com/search",
                params={"q": q, "num": "20"},
                headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"},
                timeout=10,
            )
            results.extend(_extract_emails(r.text, domain, "google-dork"))
            await asyncio.sleep(1)
        except Exception:
            pass
    return results


async def _scrape_bing(client: httpx.AsyncClient, domain: str) -> list[EmailResult]:
    try:
        r = await client.get(
            "https://www.bing.com/search",
            params={"q": f'"{domain}" email "@{domain}"', "count": "20"},
            headers={"User-Agent": "Mozilla/5.0 (compatible; bingbot/2.0)"},
            timeout=10,
        )
        return _extract_emails(r.text, domain, "bing-dork")
    except Exception:
        return []


async def _scrape_wayback(client: httpx.AsyncClient, domain: str) -> list[EmailResult]:
    try:
        r = await client.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url":    f"*.{domain}/*",
                "output": "text",
                "fl":     "original",
                "limit":  "100",
                "filter": "statuscode:200",
            },
            timeout=20,
        )
        return _extract_emails(r.text, domain, "wayback")
    except Exception:
        return []


async def _scrape_github(client: httpx.AsyncClient, domain: str) -> list[EmailResult]:
    try:
        r = await client.get(
            "https://api.github.com/search/commits",
            params={"q": domain, "per_page": "30"},
            headers={"Accept": "application/vnd.github.cloak-preview"},
            timeout=15,
        )
        return _extract_emails(r.text, domain, "github")
    except Exception:
        return []


async def _scrape_pastebin(client: httpx.AsyncClient, domain: str) -> list[EmailResult]:
    try:
        r = await client.get(f"https://psbdmp.ws/api/v3/search/{domain}", timeout=10)
        return _extract_emails(r.text, domain, "pastebin")
    except Exception:
        return []


def _detect_pattern(emails: list[str], domain: str) -> list[str]:
    patterns = []
    locals_  = [e.split("@")[0] for e in emails if domain in e]
    has_dot   = sum(1 for l in locals_ if "." in l)
    has_under = sum(1 for l in locals_ if "_" in l)
    has_short = sum(1 for l in locals_ if len(l) <= 3)
    if has_dot   > len(locals_) // 2: patterns.append("first.last@domain")
    if has_under > len(locals_) // 2: patterns.append("first_last@domain")
    if has_short > len(locals_) // 2: patterns.append("flast@domain")
    return patterns


async def _check_hibp(
    client:   httpx.AsyncClient,
    email:    str,
    hibp_key: str = "",
) -> Optional[dict]:
    try:
        r = await client.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
            headers={"hibp-api-key": hibp_key, "User-Agent": "Prothos"},
            timeout=10,
        )
        if r.status_code == 200:
            breaches = r.json()
            return {
                "email":    email,
                "breaches": [b.get("Name") for b in breaches],
                "count":    len(breaches),
            }
    except Exception:
        pass
    return None


async def check_breaches(
    emails:   list[str],
    hibp_key: Optional[str] = None,
) -> list[dict]:
    results = []
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for email in emails:
            console.print(f"[dim]    Checking {email}...[/dim]")
            result = await _check_hibp(client, email, hibp_key or "")
            if result:
                results.append(result)
                console.print(
                    f"  [red][!][/red] [cyan]{email}[/cyan] "
                    f"found in [red]{result['count']}[/red] breach(es): "
                    f"[dim]{', '.join(result['breaches'][:3])}[/dim]"
                )
            await asyncio.sleep(1.5)
    return results


def generate_spray_list(
    emails:    list[str],
    passwords: Optional[list[str]] = None,
    output:    Optional[str]       = None,
) -> list[tuple[str, str]]:

    default_passwords = [
        "Password1",   "Password123",  "Password1!",
        "Welcome1",    "Welcome123",   "Welcome1!",
        "Summer2024!", "Winter2024!",  "Spring2024!", "Fall2024!",
        "Company2024!","Admin2024!",   "Login2024!",
        "January2024!","February2024!","March2024!",
        "Passw0rd",    "Passw0rd!",    "P@ssw0rd",
        "Qwerty123!",  "123456789!",   "111111111!",
        "ChangeMe1!",  "LetMeIn1!",    "Welcome@1",
    ]

    passwords = passwords or default_passwords
    pairs     = [(email, pwd) for pwd in passwords for email in emails]

    console.print(
        f"\n[dim]    Spray list: {len(emails)} emails x "
        f"{len(passwords)} passwords = {len(pairs)} pairs[/dim]"
    )

    if output:
        try:
            with open(output, "w") as f:
                for email, pwd in pairs:
                    f.write(f"{email}:{pwd}\n")
            console.print(f"[dim]    [+] Spray list saved to {output}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save spray list: {e}[/red]")

    return pairs


def _display(report: EmailReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.domain}[/bold white]  "
        f"[dim]emails:[/dim] [green]{len(report.unique)}[/green]  "
        f"[dim]patterns:[/dim] {len(report.patterns)}",
        title="[bold red]Email Harvester — Summary[/bold red]",
        border_style="red",
    ))

    if not report.unique:
        console.print("[dim]    No emails found.[/dim]\n")
        return

    if report.patterns:
        console.print(f"\n[dim]Detected email patterns:[/dim]")
        for p in report.patterns:
            console.print(f"  [cyan]→ {p}[/cyan]")

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Email",      min_width=35, style="cyan")
    table.add_column("Source",     width=18,     style="dim")
    table.add_column("Confidence", width=10)

    seen = set()
    for r in report.emails:
        if r.email not in seen:
            seen.add(r.email)
            color = "green" if r.confidence == "high" else "yellow" if r.confidence == "medium" else "dim"
            table.add_row(r.email, r.source, f"[{color}]{r.confidence}[/{color}]")

    console.print(table)
    console.print()


async def _harvest_async(domain: str) -> EmailReport:
    report      = EmailReport(target=domain, domain=domain)
    all_results: list[EmailResult] = []

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:

        sources = [
            ("hunter.io",    _scrape_hunter(client, domain)),
            ("phonebook.cz", _scrape_phonebook(client, domain)),
            ("emailrep.io",  _scrape_emailrep(client, domain)),
            ("google-dork",  _scrape_google(client, domain)),
            ("bing-dork",    _scrape_bing(client, domain)),
            ("wayback",      _scrape_wayback(client, domain)),
            ("github",       _scrape_github(client, domain)),
            ("pastebin",     _scrape_pastebin(client, domain)),
        ]

        for name, coro in sources:
            console.print(f"[dim]    Scraping {name}...[/dim]")
            try:
                results = await coro
                if results:
                    all_results.extend(results)
                    console.print(f"[dim]    {name}: {len(results)} emails[/dim]")
            except Exception as e:
                report.errors.append(f"{name}: {e}")

    seen   = set()
    unique = []
    for r in all_results:
        if r.email not in seen:
            seen.add(r.email)
            unique.append(r.email)
            report.emails.append(r)
            console.print(
                f"  [green][+][/green] [cyan]{r.email}[/cyan] "
                f"[dim]({r.source})[/dim]"
            )

    report.unique      = unique
    report.patterns    = _detect_pattern(unique, domain)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_email_harvester(
    target:       str,
    check_hibp:   bool          = False,
    hibp_key:     Optional[str] = None,
    spray:        bool          = False,
    spray_output: Optional[str] = None,
    save_json:    Optional[str] = None,
) -> EmailReport:

    parsed = urlparse(target)
    domain = parsed.hostname or target

    console.print(
        f"\n[bold red][*][/bold red] Email Harvester → "
        f"[bold white]{domain}[/bold white]"
    )

    report = asyncio.run(_harvest_async(domain))
    _display(report)

    if check_hibp and report.unique:
        console.print(f"\n[bold red][*][/bold red] Checking breaches via HIBP...")
        asyncio.run(check_breaches(report.unique[:20], hibp_key))

    if spray and report.unique:
        console.print(f"\n[bold red][*][/bold red] Generating spray list...")
        generate_spray_list(report.unique, output=spray_output)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report