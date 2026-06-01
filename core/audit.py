"""Audit trail — append-only JSONL record of every offensive action.

Always on, regardless of lab/RoE settings. Each line is one event so the log
survives crashes and is trivially greppable. Exploit and post-ex modules call
`audit(...)` for every payload sent, file read, shell obtained, or artifact
planted — this is what makes the engagement defensible and reversible.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_lock = threading.Lock()
_log_path: Optional[Path] = None


def init_audit(session_id: str = "session", output_dir: str | Path = "output") -> Path:
    global _log_path
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    _log_path = out / f"audit-{session_id}.jsonl"
    # touch + header event
    _write({
        "event":   "audit_start",
        "session": session_id,
    })
    return _log_path


def _resolve_path() -> Path:
    global _log_path
    if _log_path is None:
        init_audit()
    return _log_path


def _write(record: dict):
    record = {"ts": datetime.now(timezone.utc).isoformat(), **record}
    line = json.dumps(record, default=str, ensure_ascii=False)
    path = _resolve_path()
    with _lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def audit(
    action:  str,
    *,
    module:  str = "",
    target:  str = "",
    payload: Optional[str] = None,
    result:  str = "",
    severity: str = "info",
    **extra: Any,
):
    """Record an offensive action. Never raises — auditing must not break a run."""
    try:
        _write({
            "event":    "action",
            "action":   action,
            "module":   module,
            "target":   target,
            "payload":  payload,
            "result":   result,
            "severity": severity,
            **extra,
        })
    except Exception:
        pass


def audit_artifact(
    kind:     str,
    location: str,
    *,
    module:   str = "",
    target:   str = "",
    cleanup:  str = "",
    **extra: Any,
):
    """Record something planted on the target so it can be cleaned up later.

    `kind` e.g. 'webshell', 'persistence', 'file', 'user'. `cleanup` is a
    human/operator instruction (or command) to remove it.
    """
    try:
        _write({
            "event":    "artifact",
            "kind":     kind,
            "location": location,
            "module":   module,
            "target":   target,
            "cleanup":  cleanup,
            **extra,
        })
    except Exception:
        pass


def read_events(path: Optional[str | Path] = None) -> list[dict]:
    p = Path(path) if path else _resolve_path()
    if not p.exists():
        return []
    events = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def artifacts(path: Optional[str | Path] = None) -> list[dict]:
    """All planted-artifact events — the basis for the cleanup report."""
    return [e for e in read_events(path) if e.get("event") == "artifact"]
