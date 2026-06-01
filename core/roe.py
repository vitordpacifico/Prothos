"""Rules of Engagement — the contract that authorizes a Prothos run.

An RoE file (JSON) declares what is in scope, what is excluded, whether active
exploitation is consented to, and operational limits (rate, test windows).
It is loaded once at startup and wires the ScopeGuard. Without a valid RoE
*and* explicit exploit consent, exploitation modules refuse to run — unless
lab mode is set, which is meant for CTF / owned machines only.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, time
from pathlib import Path
from typing import Optional

from core.scope import init_guard


@dataclass
class TestWindow:
    """A daily window during which active testing is permitted (UTC, HH:MM)."""
    start: str = "00:00"
    end:   str = "23:59"

    def _parse(self, hhmm: str) -> time:
        h, m = hhmm.split(":")
        return time(int(h), int(m))

    def is_open(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.utcnow()
        cur = now.time()
        return self._parse(self.start) <= cur <= self._parse(self.end)


@dataclass
class RoE:
    client:        str             = ""
    engagement:    str             = ""
    authorized_by: str             = ""
    scope:         list[str]       = field(default_factory=list)
    exclude:       list[str]       = field(default_factory=list)

    allow_exploit: bool            = False   # consent for active exploitation
    allow_postex:  bool            = False   # consent for post-exploitation
    lab:           bool            = False   # CTF / owned boxes — disables scope block

    max_rps:       float           = 10.0    # operational rate limit
    windows:       list[TestWindow] = field(default_factory=list)
    notes:         str             = ""

    # --- predicates ---------------------------------------------------------

    def window_open(self, now: Optional[datetime] = None) -> bool:
        if not self.windows:
            return True
        return any(w.is_open(now) for w in self.windows)

    def can_exploit(self) -> tuple[bool, str]:
        if self.lab:
            return True, "lab mode"
        if not self.allow_exploit:
            return False, "exploitation not consented in RoE (allow_exploit=false)"
        if not self.window_open():
            return False, "outside authorized test window"
        return True, "authorized"

    def can_postex(self) -> tuple[bool, str]:
        ok, reason = self.can_exploit()
        if not ok:
            return ok, reason
        if not self.lab and not self.allow_postex:
            return False, "post-exploitation not consented in RoE (allow_postex=false)"
        return True, "authorized"

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def activate(self):
        """Wire this RoE into the global ScopeGuard."""
        init_guard(scope=self.scope, exclude=self.exclude, lab=self.lab)
        return self


def load_roe(path: str | Path) -> RoE:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    windows = [TestWindow(**w) for w in data.pop("windows", [])]
    roe = RoE(windows=windows, **{k: v for k, v in data.items() if k in RoE.__dataclass_fields__})
    return roe


def lab_roe(scope: Optional[list[str]] = None) -> RoE:
    """Convenience RoE for CTF / lab: scope is informational, nothing is blocked."""
    return RoE(
        engagement="lab",
        scope=scope or [],
        lab=True,
        allow_exploit=True,
        allow_postex=True,
        notes="lab mode — scope guard disabled, intended for owned/CTF targets only",
    )


_roe: Optional[RoE] = None


def init_roe(roe: RoE) -> RoE:
    global _roe
    _roe = roe.activate()
    return _roe


def get_roe() -> RoE:
    """Active RoE. Defaults to a fail-closed RoE (no scope, no exploit)."""
    global _roe
    if _roe is None:
        _roe = RoE().activate()
    return _roe
