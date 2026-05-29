import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from rich.console import Console

console = Console()

SARIF_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

SECURITY_SEVERITY = {
    "critical": "9.5",
    "high":     "7.5",
    "medium":   "5.0",
    "low":      "3.1",
    "info":     "0.0",
}


def _as_dict(session: Any) -> dict:
    if hasattr(session, "to_dict"):
        return session.to_dict()
    if isinstance(session, dict):
        return session
    return {}


def _findings(data: dict) -> list[dict]:
    items = data.get("findings_detail") or data.get("findings") or []
    return [f for f in items if isinstance(f, dict)]


def _rule_id(f: dict) -> str:
    base = f.get("module") or f.get("category") or "prothos"
    title = f.get("title") or f.get("issue") or ""
    slug = re.sub(r"[^\w]+", "-", f"{base}-{title}".lower()).strip("-")
    return slug or "prothos-finding"


def _build_sarif(data: dict) -> dict:
    findings = _findings(data)

    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rid = _rule_id(f)
        sev = f.get("severity", "info")
        title = f.get("title") or f.get("issue") or f.get("module", "finding")

        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": str(f.get("description") or title)},
                "helpUri": "https://owasp.org/www-project-top-ten/",
                "properties": {
                    "security-severity": SECURITY_SEVERITY.get(sev, "0.0"),
                    "tags": ["security", f.get("category", "vuln")],
                },
                "defaultConfiguration": {"level": SARIF_LEVEL.get(sev, "note")},
            }

        location_uri = f.get("url") or f.get("target") or data.get("target") or "unknown"
        message = str(f.get("description") or title)
        if f.get("evidence"):
            message += f"\nEvidence: {str(f.get('evidence'))[:500]}"
        if f.get("payload"):
            message += f"\nPayload: {str(f.get('payload'))[:500]}"

        results.append({
            "ruleId": rid,
            "level": SARIF_LEVEL.get(sev, "note"),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": location_uri},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "severity": sev,
                "param": f.get("param"),
                "cve": f.get("cve"),
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Prothos",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/prothos",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }],
    }


def run_sarif_export(session: Any, output_path: str) -> str:
    data = _as_dict(session)
    findings = _findings(data)
    console.print(f"\n[bold red][*][/bold red] SARIF 2.1.0 export → [bold white]{output_path}[/bold white]")
    console.print(f"[dim]    Findings: {len(findings)}[/dim]")

    sarif = _build_sarif(data)
    try:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
        console.print(f"[dim][+] Saved to {output_path}[/dim]")
    except OSError as e:
        console.print(f"[red][!] Failed to save: {e}[/red]")

    return output_path
