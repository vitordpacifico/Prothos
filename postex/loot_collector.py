"""Loot collector — harvest and structure sensitive data from an engagement.

Pulls together credentials/secrets/tokens already surfaced during the run:
exploit loot recorded in the audit trail, secrets in session findings, and
(optionally) files dumped to a local directory. Reuses the secret-detection
rules from core.analyzer so detection logic lives in one place. Gated by
postex._base.preflight.
"""

import re
from pathlib import Path
from typing import Optional
from postex._base import PostexReport, preflight, display, save, header, console
from core import audit
from core.analyzer import RULES

# reuse the analyzer's secret rules (category == "secret")
SECRET_RULES = [(rid, pat, label) for (rid, pat, label, sev, cat) in RULES if cat == "secret"]


def _scan_text(text: str, source: str, report: PostexReport):
    for rid, pattern, label in SECRET_RULES:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            value = (m.group(0) or "")[:120].strip()
            if value:
                report.add(label, f"{source}: {value}", "critical", finding=True)
                report.add_loot(f"{label} @ {source}: {value}")


def run_loot_collector(
    target:        str,
    loot_dir:      Optional[str] = None,
    allow_postex:  bool          = False,
    lab:           bool          = False,
    save_json:     Optional[str] = None,
    **_,
) -> PostexReport:
    header("loot_collector", target, "collect")
    refusal = preflight("loot_collector", target, allow_postex, lab)
    if refusal is not None:
        return refusal

    report = PostexReport(module="loot_collector", target=target, mode="collect")

    # 1) audit-trail loot (exploit modules record creds/data here)
    for ev in audit.read_events():
        loot = ev.get("loot") or ev.get("result", "")
        if ev.get("event") == "action" and ev.get("severity") == "critical":
            text = " ".join(str(v) for v in (ev.get("payload"), ev.get("result")) if v)
            _scan_text(text, f"audit/{ev.get('module','?')}", report)

    # 2) session findings (secrets surfaced during recon/scan)
    from core.session import get_session
    sess = get_session()
    if sess:
        for f in sess.findings:
            blob = f"{f.title} {f.description} {f.evidence}"
            _scan_text(blob, f"finding/{f.module}", report)

    # 3) local loot directory (dumped files / responses)
    if loot_dir:
        d = Path(loot_dir)
        if d.exists():
            for fp in d.rglob("*"):
                if fp.is_file() and fp.stat().st_size < 2_000_000:
                    try:
                        _scan_text(fp.read_text(encoding="utf-8", errors="replace"),
                                   f"file/{fp.name}", report)
                    except Exception:
                        continue

    if not report.findings:
        report.add("scan complete", "no secrets/credentials collected")

    report.finish()
    display(report)
    save(report, save_json)
    return report
