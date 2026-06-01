"""Report -> Session adapter.

Every Prothos module returns its own `Report` dataclass with a `to_dict()`.
This bridges those heterogeneous reports into the unified `Session.findings`
list so the engine, CLI and exporters all see one finding model. Extracted
from the CLI so the Engine pipeline can ingest the same way.
"""

from typing import Optional
from core.session import Session

VALID_SEV = {"critical", "high", "medium", "low", "info"}


def _title_for(f: dict, module: str) -> str:
    return str(
        f.get("title") or f.get("issue") or f.get("cve") or f.get("technique")
        or f.get("engine") or f.get("kind") or f.get("service") or module
    )[:200]


def ingest_report(
    session:  Session,
    module:   str,
    category: str,
    report,
) -> int:
    """Pull findings out of `report` into `session`. Returns count added."""
    if report is None:
        return 0
    try:
        d = report.to_dict() if hasattr(report, "to_dict") else (
            report if isinstance(report, dict) else {})
    except Exception:
        return 0

    findings = d.get("findings") or d.get("findings_detail") or []
    count = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = f.get("severity", "info")
        if sev not in VALID_SEV:
            sev = "info"
        title = _title_for(f, module)
        try:
            session.finding(
                module=module,
                category=category,
                severity=sev,
                title=title,
                description=str(
                    f.get("description") or f.get("detail")
                    or f.get("evidence") or title)[:1000],
                url=f.get("url") or f.get("subdomain") or f.get("target"),
                param=f.get("param"),
                payload=f.get("payload"),
                evidence=str(f.get("evidence") or "")[:1000],
                cve=f.get("cve"),
                extra={k: v for k, v in f.items() if k in (
                    "dbms", "technique", "status", "delay", "location", "kind")},
            )
            count += 1
        except Exception:
            continue

    if count:
        session.mark_done(module)
    return count
