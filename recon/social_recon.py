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

console = Console()

@dataclass
class SocialProfile:
    platform:  str
    url:       str
    username:  Optional[str] = None
    name:      Optional[str] = None
    bio:       Optional[str] = None
    followers: Optional[int] = None
    found:     bool          = True
    notes:     list[str]     = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()

@dataclass
class SocialEmployee:
    name:     str
    title:    Optional[str] = None
    company:  Optional[str] = None
    location: Optional[str] = None
    linkedin: Optional[str] = None
    source:   str           = "linkedin"

    def to_dict(self) -> dict:
        return self.__dict__.copy()

@dataclass
class SocialReport:
    target:      str
    started_at:  str                   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]        = None
    profiles:    list[SocialProfile]  = field(default_factory=list)
    employees:   list[SocialEmployee] = field(default_factory=list)
    usernames:   list[str]           = field(default_factory=list)
    emails:      list[str]           = field(default_factory=list)
    errors:      list[str]          = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["profiles"]  = [p.to_dict() for p in self.profiles]
        d["employees"] = [e.to_dict() for e in self.employees]
        return d

SOCIAL_PLATFORMS = {
    "twitter":   "https://twitter.com/{username}",
    "linkedin":  "https://www.linkedin.com/company/{username}",
    "github":    "https://github.com/{username}",
    "instagram": "https://www.instagram.com/{username}",
    "facebook":  "https://www.facebook.com/{username}",
    "youtube":   "https://www.youtube.com/@{username}",
    "reddit":    "https://www.reddit.com/r/{username}",
    "medium":    "https://medium.com/@{username}",
    "telegram":  "https://t.me/{username}",
    "tiktok":    "https://www.tiktok.com/@{username}",
    "pinterest": "https://www.pinterest.com/{username}",
    "glassdoor": "https://www.glassdoor.com/Overview/Working-at-{username}.htm",
}

USERNAME_VARIANTS = [
    "{base}", "{base}official", "{base}hq", "{base}inc",
    "{base}corp", "{base}io", "{base}app", "{base}team",
    "{base}dev", "{base}security", "{base}eng", "{base}tech",
]

FAKE_TITLES = {
    "buildresponder", "telegram messenger", "discord - group chat",
    "tiktok - make your day", "instagram", "facebook", "discord",
    "that's all fun", "first_name last_name", "pinterest",
    "discord - a new way to chat", "sign up for instagram",
    "log into facebook", "youtube", "reddit", "medium",
    "telegram: contact", "telegram: view", "telegram messenger",
}

STRICT_PLATFORMS = {"telegram", "pinterest", "glassdoor"}

def _build_usernames(domain: str) -> list[str]:
    base = domain.split(".")[0].lower()
    return list(set([v.format(base=base) for v in USERNAME_VARIANTS]))

def _build_person_variants(target: str) -> list[str]:
    parts = target.lower().split()
    nick  = target.lower().replace(" ", "")
    local = target.split("@")[0] if "@" in target else nick

    variants = list(set([
        local,
        nick,
        target.lower().replace(" ", "."),
        target.lower().replace(" ", "_"),
        target.lower().replace(" ", "-"),
        nick + "official",
        nick + "hq",
        nick + "real",
        parts[0] if parts else nick,
        parts[-1] if len(parts) > 1 else nick,
        (parts[0][0] + parts[-1]) if len(parts) >= 2 else nick,
        (parts[0] + parts[-1][0]) if len(parts) >= 2 else nick,
        (parts[0] + "." + parts[-1]) if len(parts) >= 2 else nick,
    ]))

    return [v for v in variants if " " not in v]

async def _check_platform(
    client:   httpx.AsyncClient,
    platform: str,
    url:      str,
    username: str,
    sem:      asyncio.Semaphore,
) -> Optional[SocialProfile]:

    async with sem:
        try:
            r = await client.get(url, timeout=8)

            if r.status_code == 404:
                return None
            if r.status_code not in (200, 301, 302):
                return None

            profile = SocialProfile(platform=platform, url=url, found=True)
            body    = r.text

            for pattern in [
                r'<title[^>]*>([^<|]+)',
                r'"name"\s*:\s*"([^"]+)"',
                r'og:title.*?content="([^"]+)"',
            ]:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    name = m.group(1).strip()
                    if name and len(name) > 2:
                        profile.name = name[:80]
                        break

            if profile.name and any(fake in profile.name.lower() for fake in FAKE_TITLES):
                profile.name = None

            for pattern in [
                r'"description"\s*:\s*"([^"]{10,})"',
                r'og:description.*?content="([^"]{10,})"',
                r'<meta name="description"[^>]+content="([^"]{10,})"',
            ]:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    profile.bio = m.group(1).strip()[:120]
                    break

            for pattern in [
                r'"followers_count"\s*:\s*(\d+)',
                r'"followerCount"\s*:\s*(\d+)',
                r'(\d[\d,]+)\s*[Ff]ollowers',
            ]:
                m = re.search(pattern, body)
                if m:
                    try:
                        profile.followers = int(m.group(1).replace(",", ""))
                        break
                    except Exception:
                        pass

            if platform in STRICT_PLATFORMS:
                if not profile.name:
                    return None
                if username.lower() not in profile.name.lower():
                    return None

            if not profile.name and not profile.followers and not profile.bio:
                return None

            return profile

        except Exception:
            return None

async def _scrape_linkedin_employees(
    client: httpx.AsyncClient,
    domain: str,
) -> list[SocialEmployee]:
    employees = []
    try:
        for q in [f'site:linkedin.com/in "{domain}"', f'site:linkedin.com/in "@{domain}"']:
            r = await client.get(
                "https://www.google.com/search",
                params={"q": q, "num": "20"},
                headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"},
                timeout=10,
            )
            names = re.findall(
                r'linkedin\.com/in/[^"]+.*?<[^>]+>([A-Z][a-z]+ [A-Z][a-z]+)',
                r.text,
            )
            urls = re.findall(r'linkedin\.com/in/[\w\-]+', r.text)
            for i, url in enumerate(urls[:10]):
                employees.append(SocialEmployee(
                    name=(names[i] if i < len(names) else url.split("/")[-1].replace("-", " ").title()),
                    linkedin=f"https://www.{url}",
                    company=domain,
                    source="google-linkedin-dork",
                ))
            await asyncio.sleep(1)
    except Exception:
        pass
    return employees

async def _scrape_twitter_mentions(
    client: httpx.AsyncClient,
    domain: str,
) -> list[str]:
    try:
        r = await client.get(
            "https://www.google.com/search",
            params={"q": f'site:twitter.com "{domain}"', "num": "10"},
            headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"},
            timeout=10,
        )
        matches = re.findall(r'twitter\.com/([A-Za-z0-9_]{3,})', r.text)
        return list(set([
            m for m in matches
            if m.lower() not in ("intent", "share", "search", "home", "explore")
        ]))
    except Exception:
        return []

async def _scrape_glassdoor(
    client: httpx.AsyncClient,
    domain: str,
) -> list[SocialEmployee]:
    employees = []
    try:
        base = domain.split(".")[0]
        r    = await client.get(
            "https://www.google.com/search",
            params={"q": f'site:glassdoor.com "{base}" employee reviews', "num": "5"},
            headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"},
            timeout=10,
        )
        for name, title in re.findall(
            r'([A-Z][a-z]+ [A-Z][a-z]+)\s*[-–]\s*([A-Za-z ]+)\s*at\s*', r.text
        )[:10]:
            employees.append(SocialEmployee(
                name=name, title=title.strip(),
                company=base, source="glassdoor",
            ))
    except Exception:
        pass
    return employees

async def _run_platforms(
    client:    httpx.AsyncClient,
    usernames: list[str],
    sem:       asyncio.Semaphore,
) -> list[SocialProfile]:
    tasks = []
    for username in usernames:
        for platform, url_tpl in SOCIAL_PLATFORMS.items():
            url = url_tpl.format(username=username)
            tasks.append((platform, url, username, _check_platform(client, platform, url, username, sem)))

    results  = await asyncio.gather(*[t[3] for t in tasks], return_exceptions=True)
    profiles = []
    seen     = set()

    for (platform, url, username, _), result in zip(tasks, results):
        if isinstance(result, SocialProfile) and result.url not in seen:
            seen.add(result.url)
            profiles.append(result)
            console.print(
                f"  [green][+][/green] [cyan]{platform}[/cyan] {result.url}"
                + (f" — {result.name}" if result.name else "")
            )

    return profiles

def _display(report: SocialReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]profiles:[/dim] [green]{len(report.profiles)}[/green]  "
        f"[dim]employees:[/dim] {len(report.employees)}  "
        f"[dim]usernames:[/dim] {len(report.usernames)}",
        title="[bold red]Social Recon — Summary[/bold red]",
        border_style="red",
    ))

    if report.profiles:
        console.print(f"\n[dim]Social profiles found:[/dim]")
        table = Table(
            show_header=True,
            header_style="bold red",
            border_style="dim",
            show_lines=False,
            expand=True,
        )
        table.add_column("Platform",  width=12,  style="cyan",  no_wrap=True)
        table.add_column("URL",       width=55,  no_wrap=True)
        table.add_column("Name",      width=30,  style="dim",   no_wrap=True)
        table.add_column("Followers", width=10,  style="dim",   no_wrap=True, justify="right")

        for p in report.profiles:
            table.add_row(
                p.platform,
                p.url,
                (p.name or "-")[:30],
                str(p.followers) if p.followers else "-",
            )
        console.print(table)

    if report.employees:
        console.print(f"\n[dim]Employees found ({len(report.employees)}):[/dim]")
        table = Table(
            show_header=True,
            header_style="bold red",
            border_style="dim",
            show_lines=False,
            expand=True,
        )
        table.add_column("Name",     width=25, style="white", no_wrap=True)
        table.add_column("Title",    width=25, style="dim",   no_wrap=True)
        table.add_column("Source",   width=22, style="dim",   no_wrap=True)
        table.add_column("LinkedIn", width=50, style="cyan",  no_wrap=True)
        for e in report.employees[:20]:
            table.add_row(e.name, e.title or "-", e.source, e.linkedin or "-")
        console.print(table)

    if report.usernames:
        console.print(f"\n[dim]Related usernames:[/dim]")
        for u in report.usernames[:15]:
            console.print(f"  [cyan]→ {u}[/cyan]")

    console.print()

async def _social_async(domain: str) -> SocialReport:
    report    = SocialReport(target=domain)
    usernames = _build_usernames(domain)
    sem       = asyncio.Semaphore(10)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:
        console.print(f"[dim]    Checking {len(usernames)} variants across {len(SOCIAL_PLATFORMS)} platforms...[/dim]")
        report.profiles = await _run_platforms(client, usernames, sem)

        console.print(f"[dim]    Scraping LinkedIn employees...[/dim]")
        report.employees.extend(await _scrape_linkedin_employees(client, domain))

        console.print(f"[dim]    Checking Glassdoor...[/dim]")
        report.employees.extend(await _scrape_glassdoor(client, domain))

        console.print(f"[dim]    Scraping Twitter mentions...[/dim]")
        report.usernames = await _scrape_twitter_mentions(client, domain)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report

async def _person_async(target: str) -> SocialReport:
    report   = SocialReport(target=target)
    variants = _build_person_variants(target)
    sem      = asyncio.Semaphore(10)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)"},
    ) as client:
        console.print(f"[dim]    Variants: {len(variants)}  Platforms: {len(SOCIAL_PLATFORMS)}[/dim]")
        report.profiles = await _run_platforms(client, variants, sem)

        console.print(f"[dim]    Scraping LinkedIn...[/dim]")
        report.employees = await _scrape_linkedin_employees(client, target)

        console.print(f"[dim]    Checking Twitter mentions...[/dim]")
        report.usernames = await _scrape_twitter_mentions(client, target)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report

def run_social_recon(
    target:    str,
    save_json: Optional[str] = None,
) -> SocialReport:

    parsed = urlparse(target)
    domain = parsed.hostname or target

    console.print(f"\n[bold red][*][/bold red] Social Recon → [bold white]{domain}[/bold white]")

    report = asyncio.run(_social_async(domain))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report

def run_person_recon(
    target:    str,
    save_json: Optional[str] = None,
) -> SocialReport:

    console.print(f"\n[bold red][*][/bold red] Person Recon → [bold white]{target}[/bold white]")

    report = asyncio.run(_person_async(target))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report