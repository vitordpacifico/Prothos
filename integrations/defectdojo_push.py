import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

SEVERITY_MAP = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
}

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "cyan",
}


@dataclass
class PushResult:
    title:      str
    severity:   str
    pushed:     bool
    dd_id:      Optional[int] = None
    error:      str           = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class DefectDojoReport:
    api_url:       str
    engagement_id: Optional[int]
    started_at:    str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:   Optional[str]       = None
    test_id:       Optional[int]       = None
    pushed:        int                 = 0
    failed:        int                 = 0
    results:       list[PushResult]    = field(default_factory=list)
    errors:        list[str]           = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["results"] = [r.to_dict() for r in self.results]
        return d


def _normalize(findings: Any) -> list[dict]:
    if hasattr(findings, "to_dict"):
        data = findings.to_dict()
        items = data.get("findings_detail") or data.get("findings") or []
    elif isinstance(findings, dict):
        items = findings.get("findings_detail") or findings.get("findings") or []
    elif isinstance(findings, list):
        items = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
    else:
        items = []
    return [f for f in items if isinstance(f, dict)]


async def _create_test(client, base, headers, engagement_id) -> Optional[int]:
    try:
        r = await client.post(
            f"{base}/api/v2/tests/",
            headers=headers,
            json={
                "engagement": engagement_id,
                "test_type": 1,
                "target_start": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "target_end": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "title": "Prothos automated scan",
            },
            timeout=20,
        )
        if r.status_code in (200, 201):
            return r.json().get("id")
    except Exception:
        pass
    return None


async def _push_finding(client, base, headers, test_id, f, sem) -> PushResult:
    title = f.get("title") or f.get("issue") or f.get("module", "Prothos finding")
    sev = f.get("severity", "info")
    async with sem:
        payload = {
            "test": test_id,
            "title": title[:511],
            "severity": SEVERITY_MAP.get(sev, "Info"),
            "description": str(f.get("description") or title),
            "mitigation": str(f.get("remediation") or "See OWASP guidance."),
            "active": True,
            "verified": False,
            "numerical_severity": {"Critical": "S0", "High": "S1", "Medium": "S2", "Low": "S3", "Info": "S4"}.get(SEVERITY_MAP.get(sev, "Info"), "S4"),
        }
        steps = []
        if f.get("url"):
            steps.append(f"URL: {f.get('url')}")
        if f.get("param"):
            steps.append(f"Parameter: {f.get('param')}")
        if f.get("payload"):
            steps.append(f"Payload: {f.get('payload')}")
        if f.get("evidence"):
            steps.append(f"Evidence: {str(f.get('evidence'))[:500]}")
        if steps:
            payload["steps_to_reproduce"] = "\n".join(steps)
        if f.get("cve"):
            payload["cve"] = f.get("cve")

        try:
            r = await client.post(f"{base}/api/v2/findings/", headers=headers, json=payload, timeout=20)
            if r.status_code in (200, 201):
                result = PushResult(title=title, severity=sev, pushed=True, dd_id=r.json().get("id"))
            else:
                result = PushResult(title=title, severity=sev, pushed=False,
                                    error=f"HTTP {r.status_code}: {r.text[:120]}")
        except Exception as e:
            result = PushResult(title=title, severity=sev, pushed=False, error=str(e)[:120])

    _print_result(result)
    return result


def _print_result(r: PushResult):
    if r.pushed:
        color = SEVERITY_COLOR.get(r.severity, "white")
        console.print(f"  [green][+][/green] [{color}]{r.severity}[/{color}] {r.title[:60]} [dim](#{r.dd_id})[/dim]")
    else:
        console.print(f"  [red][!][/red] {r.title[:50]} — {r.error}")


def _display(report: DefectDojoReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.api_url}[/bold white]  "
        f"[dim]engagement:[/dim] {report.engagement_id}  "
        f"[dim]test:[/dim] {report.test_id}  "
        f"[dim]pushed:[/dim] [green]{report.pushed}[/green]  "
        f"[dim]failed:[/dim] [red]{report.failed}[/red]",
        title="[bold red]DefectDojo Push — Summary[/bold red]",
        border_style="red",
    ))
    console.print()


async def _dd_async(findings, base, api_key, engagement_id, concurrency) -> DefectDojoReport:
    report = DefectDojoReport(api_url=base, engagement_id=engagement_id)
    items = _normalize(findings)
    headers = {"Authorization": f"Token {api_key}", "Content-Type": "application/json"}
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(verify=False) as client:
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Pushing to DefectDojo...", total=None)

            report.test_id = await _create_test(client, base, headers, engagement_id)
            if report.test_id is None:
                report.errors.append("Could not create test record in engagement")
                console.print("[red][!] Failed to create DefectDojo test — check api_url/api_key/engagement_id[/red]")
                report.finished_at = datetime.now(timezone.utc).isoformat()
                return report

            tasks = [_push_finding(client, base, headers, report.test_id, f, sem) for f in items]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                report.results.append(result)
                if result.pushed:
                    report.pushed += 1
                else:
                    report.failed += 1

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_defectdojo_push(
    findings:      Any,
    api_url:       str,
    api_key:       str,
    engagement_id: int,
    concurrency:   int            = 5,
    proxy:         Optional[str]  = None,
    save_json:     Optional[str]  = None,
) -> DefectDojoReport:

    base = api_url.rstrip("/")
    console.print(f"\n[bold red][*][/bold red] DefectDojo Push → [bold white]{base}[/bold white]")
    console.print(f"[dim]    Findings: {len(_normalize(findings))}  Engagement: {engagement_id}[/dim]")

    report = asyncio.run(_dd_async(findings, base, api_key, engagement_id, concurrency))
    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
