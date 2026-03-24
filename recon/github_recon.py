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
class GitHubSecret:
    kind:     str
    value:    str
    file:     str
    repo:     str
    url:      str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class GitHubRepo:
    name:        str
    full_name:   str
    url:         str
    description: str              = ""
    stars:       int              = 0
    forks:       int              = 0
    language:    Optional[str]    = None
    updated_at:  Optional[str]    = None
    topics:      list[str]        = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class GitHubUser:
    login:      str
    name:       Optional[str]  = None
    email:      Optional[str]  = None
    company:    Optional[str]  = None
    location:   Optional[str]  = None
    bio:        Optional[str]  = None
    repos:      int            = 0
    followers:  int            = 0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class GitHubReport:
    target:       str
    started_at:   str                    = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:  Optional[str]         = None
    org:          Optional[dict]        = None
    members:      list[GitHubUser]      = field(default_factory=list)
    repos:        list[GitHubRepo]      = field(default_factory=list)
    secrets:      list[GitHubSecret]    = field(default_factory=list)
    dorks:        list[dict]            = field(default_factory=list)
    emails:       list[str]            = field(default_factory=list)
    errors:       list[str]            = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["members"] = [m.to_dict() for m in self.members]
        d["repos"]   = [r.to_dict() for r in self.repos]
        d["secrets"] = [s.to_dict() for s in self.secrets]
        return d


SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}",                          "AWS Access Key"),
    (r"['\"]?aws_secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "AWS Secret"),
    (r"ghp_[A-Za-z0-9]{36}",                       "GitHub Token"),
    (r"gho_[A-Za-z0-9]{36}",                       "GitHub OAuth"),
    (r"ghs_[A-Za-z0-9]{36}",                       "GitHub App Token"),
    (r"AIza[0-9A-Za-z\-_]{35}",                    "Google API Key"),
    (r"ya29\.[0-9A-Za-z\-_]+",                     "Google OAuth Token"),
    (r"sk-[A-Za-z0-9]{48}",                        "OpenAI Key"),
    (r"xox[baprs]-[0-9A-Za-z\-]+",                 "Slack Token"),
    (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}","SendGrid Key"),
    (r"key-[a-zA-Z0-9]{32}",                       "Mailgun Key"),
    (r"['\"]?private_key['\"]?\s*[:=]\s*['\"]?-----BEGIN", "Private Key"),
    (r"['\"]?password['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Hardcoded Password"),
    (r"['\"]?secret['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",   "Hardcoded Secret"),
    (r"['\"]?api_key['\"]?\s*[:=]\s*['\"]([^'\"]{16,})['\"]", "API Key"),
    (r"jdbc:[a-z]+://[^\s\"']+",                   "Database URL"),
    (r"mongodb(\+srv)?://[^\s\"']+",               "MongoDB URL"),
    (r"redis://[^\s\"']+",                          "Redis URL"),
    (r"postgres://[^\s\"']+",                       "PostgreSQL URL"),
]

DORK_QUERIES = [
    '{domain} password',
    '{domain} secret',
    '{domain} api_key',
    '{domain} token',
    '{domain} credentials',
    '{domain} config',
    '{domain} .env',
    '{domain} database',
    '{domain} private_key',
    '{domain} access_key',
]


def _extract_secrets(content: str, file: str, repo: str, url: str) -> list[GitHubSecret]:
    found = []
    for pattern, kind in SECRET_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            value = match if isinstance(match, str) else match[0] if match else ""
            if value and len(value) > 6:
                found.append(GitHubSecret(
                    kind=kind,
                    value=value[:80],
                    file=file,
                    repo=repo,
                    url=url,
                ))
    return found


async def _get_org(
    client: httpx.AsyncClient,
    org:    str,
    token:  Optional[str],
) -> Optional[dict]:
    try:
        headers = {"Authorization": f"token {token}"} if token else {}
        r = await client.get(
            f"https://api.github.com/orgs/{org}",
            headers=headers,
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


async def _get_org_members(
    client: httpx.AsyncClient,
    org:    str,
    token:  Optional[str],
) -> list[GitHubUser]:
    members = []
    headers = {"Authorization": f"token {token}"} if token else {}
    try:
        r = await client.get(
            f"https://api.github.com/orgs/{org}/members",
            params={"per_page": "100"},
            headers=headers,
            timeout=15,
        )
        if r.status_code != 200:
            return members

        for m in r.json():
            try:
                ur = await client.get(
                    f"https://api.github.com/users/{m['login']}",
                    headers=headers,
                    timeout=8,
                )
                if ur.status_code == 200:
                    data = ur.json()
                    members.append(GitHubUser(
                        login=data.get("login", ""),
                        name=data.get("name"),
                        email=data.get("email"),
                        company=data.get("company"),
                        location=data.get("location"),
                        bio=data.get("bio"),
                        repos=data.get("public_repos", 0),
                        followers=data.get("followers", 0),
                    ))
            except Exception:
                pass

    except Exception:
        pass
    return members


async def _get_org_repos(
    client: httpx.AsyncClient,
    org:    str,
    token:  Optional[str],
) -> list[GitHubRepo]:
    repos   = []
    headers = {"Authorization": f"token {token}"} if token else {}
    page    = 1

    while len(repos) < 200:
        try:
            r = await client.get(
                f"https://api.github.com/orgs/{org}/repos",
                params={"per_page": "100", "page": str(page), "sort": "updated"},
                headers=headers,
                timeout=15,
            )
            if r.status_code != 200 or not r.json():
                break

            for repo in r.json():
                repos.append(GitHubRepo(
                    name=repo.get("name", ""),
                    full_name=repo.get("full_name", ""),
                    url=repo.get("html_url", ""),
                    description=repo.get("description") or "",
                    stars=repo.get("stargazers_count", 0),
                    forks=repo.get("forks_count", 0),
                    language=repo.get("language"),
                    updated_at=repo.get("updated_at"),
                    topics=repo.get("topics", []),
                ))
            page += 1

        except Exception:
            break

    return repos


async def _search_secrets_in_repo(
    client:    httpx.AsyncClient,
    full_name: str,
    token:     Optional[str],
) -> list[GitHubSecret]:
    secrets = []
    headers = {"Authorization": f"token {token}"} if token else {}

    sensitive_files = [
        ".env", ".env.local", ".env.dev", ".env.prod",
        "config.json", "config.yaml", "config.yml",
        "secrets.json", "credentials.json",
        "application.properties", "application.yaml",
        "docker-compose.yml", "docker-compose.yaml",
        "terraform.tfvars", ".npmrc", ".pypirc",
    ]

    for filename in sensitive_files:
        try:
            r = await client.get(
                f"https://api.github.com/repos/{full_name}/contents/{filename}",
                headers=headers,
                timeout=8,
            )
            if r.status_code == 200:
                data    = r.json()
                content = data.get("content", "")
                if content:
                    import base64
                    decoded = base64.b64decode(content).decode("utf-8", errors="replace")
                    found   = _extract_secrets(
                        decoded,
                        filename,
                        full_name,
                        data.get("html_url", ""),
                    )
                    secrets.extend(found)
                    if found:
                        console.print(
                            f"  [red][!][/red] Secrets in "
                            f"[cyan]{full_name}/{filename}[/cyan]: "
                            f"{len(found)} found"
                        )
        except Exception:
            pass

    return secrets


async def _run_dorks(
    client: httpx.AsyncClient,
    domain: str,
    token:  Optional[str],
) -> list[dict]:
    results = []
    headers = {"Authorization": f"token {token}"} if token else {}

    for query_tpl in DORK_QUERIES:
        query = query_tpl.format(domain=domain)
        try:
            r = await client.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": "10"},
                headers=headers,
                timeout=10,
            )
            if r.status_code == 200:
                data  = r.json()
                items = data.get("items", [])
                if items:
                    results.append({
                        "query": query,
                        "count": data.get("total_count", 0),
                        "items": [
                            {
                                "repo": i.get("repository", {}).get("full_name"),
                                "file": i.get("name"),
                                "url":  i.get("html_url"),
                            }
                            for i in items[:5]
                        ],
                    })
                    console.print(
                        f"  [yellow][!][/yellow] Dork [dim]{query}[/dim]: "
                        f"[yellow]{data.get('total_count', 0)}[/yellow] results"
                    )
            await asyncio.sleep(0.5)
        except Exception:
            pass

    return results


def _collect_emails(members: list[GitHubUser]) -> list[str]:
    return [m.email for m in members if m.email]


def _display(report: GitHubReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.target}[/bold white]  "
        f"[dim]members:[/dim] {len(report.members)}  "
        f"[dim]repos:[/dim] {len(report.repos)}  "
        f"[dim]secrets:[/dim] [red]{len(report.secrets)}[/red]  "
        f"[dim]dorks:[/dim] [yellow]{len(report.dorks)}[/yellow]",
        title="[bold red]GitHub Recon — Summary[/bold red]",
        border_style="red",
    ))

    if report.org:
        org = report.org
        console.print(f"\n[dim]Organization:[/dim]")
        console.print(f"  [dim]Name:[/dim]        {org.get('name') or org.get('login')}")
        console.print(f"  [dim]Members:[/dim]     {org.get('public_members_url', '').split('{')[0]}")
        console.print(f"  [dim]Repos:[/dim]       {org.get('public_repos', 0)}")
        console.print(f"  [dim]Location:[/dim]    {org.get('location') or '-'}")
        console.print(f"  [dim]Blog:[/dim]        {org.get('blog') or '-'}")
        console.print(f"  [dim]Email:[/dim]       {org.get('email') or '-'}")

    if report.members:
        console.print(f"\n[dim]Members ({len(report.members)}):[/dim]")
        table = Table(show_header=True, header_style="bold red", border_style="dim")
        table.add_column("Login",    width=20, style="cyan")
        table.add_column("Name",     width=20, style="white")
        table.add_column("Email",    width=30, style="dim")
        table.add_column("Company",  width=20, style="dim")
        table.add_column("Repos",    width=6,  style="dim")
        for m in report.members[:30]:
            table.add_row(
                m.login,
                m.name or "-",
                m.email or "-",
                (m.company or "-")[:20],
                str(m.repos),
            )
        console.print(table)

    if report.repos:
        console.print(f"\n[dim]Top repos ({min(len(report.repos), 15)}):[/dim]")
        table = Table(show_header=True, header_style="bold red", border_style="dim")
        table.add_column("Repo",      min_width=30, style="cyan")
        table.add_column("Language",  width=14, style="dim")
        table.add_column("Stars",     width=7,  style="dim")
        table.add_column("Updated",   width=12, style="dim")
        for r in sorted(report.repos, key=lambda x: x.stars, reverse=True)[:15]:
            table.add_row(
                r.name,
                r.language or "-",
                str(r.stars),
                (r.updated_at or "-")[:10],
            )
        console.print(table)

    if report.secrets:
        console.print(f"\n[bold red][!] Secrets found ({len(report.secrets)}):[/bold red]")
        table = Table(show_header=True, header_style="bold red", border_style="dim")
        table.add_column("Kind",  width=20, style="yellow")
        table.add_column("Repo",  width=30, style="cyan")
        table.add_column("File",  width=25, style="dim")
        table.add_column("Value", min_width=30, style="red")
        for s in report.secrets:
            table.add_row(s.kind, s.repo, s.file, s.value[:50])
        console.print(table)

    if report.dorks:
        console.print(f"\n[bold yellow][!] Dork results:[/bold yellow]")
        for d in report.dorks:
            console.print(f"  [yellow]→[/yellow] [dim]{d['query']}[/dim] — {d['count']} results")
            for item in d["items"][:3]:
                console.print(f"      [dim]{item['repo']} / {item['file']}[/dim]")

    if report.emails:
        console.print(f"\n[dim]Emails from members:[/dim]")
        for email in report.emails:
            console.print(f"  [cyan]→ {email}[/cyan]")

    console.print()


async def _github_async(
    domain: str,
    org:    str,
    token:  Optional[str],
    scan_secrets: bool,
    run_dorks:    bool,
) -> GitHubReport:

    report = GitHubReport(target=domain)
    headers = {"Authorization": f"token {token}"} if token else {}

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; Prothos/1.0)",
            "Accept":     "application/vnd.github.v3+json",
            **headers,
        },
    ) as client:

        console.print(f"[dim]    Fetching org info: {org}...[/dim]")
        report.org = await _get_org(client, org, token)

        console.print(f"[dim]    Fetching members...[/dim]")
        report.members = await _get_org_members(client, org, token)
        console.print(f"[dim]    Members: {len(report.members)}[/dim]")

        console.print(f"[dim]    Fetching repos...[/dim]")
        report.repos = await _get_org_repos(client, org, token)
        console.print(f"[dim]    Repos: {len(report.repos)}[/dim]")

        report.emails = _collect_emails(report.members)

        if scan_secrets and report.repos:
            console.print(f"[dim]    Scanning repos for secrets...[/dim]")
            for repo in report.repos[:20]:
                secrets = await _search_secrets_in_repo(client, repo.full_name, token)
                report.secrets.extend(secrets)

        if run_dorks:
            console.print(f"[dim]    Running GitHub dorks...[/dim]")
            report.dorks = await _run_dorks(client, domain, token)

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_github_recon(
    target:       str,
    org:          Optional[str] = None,
    token:        Optional[str] = None,
    scan_secrets: bool          = True,
    run_dorks:    bool          = True,
    save_json:    Optional[str] = None,
) -> GitHubReport:

    parsed = urlparse(target)
    domain = parsed.hostname or target

    if not org:
        org = domain.split(".")[0]

    console.print(
        f"\n[bold red][*][/bold red] GitHub Recon → "
        f"[bold white]{domain}[/bold white] "
        f"[dim](org: {org})[/dim]"
    )

    if not token:
        console.print(
            "[yellow][!] No GitHub token — rate limited to 60 req/h. "
            "Pass token='' for better results.[/yellow]"
        )

    report = asyncio.run(_github_async(
        domain=domain,
        org=org,
        token=token,
        scan_secrets=scan_secrets,
        run_dorks=run_dorks,
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