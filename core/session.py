import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

@dataclass
class Finding:
    module:      str
    category:    str
    severity:    str
    title:       str
    description: str
    target:      str
    evidence:    str                    = ""
    payload:     Optional[str]         = None
    url:         Optional[str]         = None
    param:       Optional[str]         = None
    cve:         Optional[str]         = None
    remediation: Optional[str]         = None
    tags:        list[str]             = field(default_factory=list)
    extra:       dict                  = field(default_factory=dict)
    id:          str                   = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:   str                   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    SEVERITIES = ("critical", "high", "medium", "low", "info")

    def __post_init__(self):
        if self.severity not in self.SEVERITIES:
            raise ValueError(f"[finding] Invalid severity '{self.severity}'. "
                             f"Must be one of: {self.SEVERITIES}")

    @property
    def is_critical(self) -> bool:
        return self.severity == "critical"

    @property
    def is_high(self) -> bool:
        return self.severity == "high"

    def to_dict(self) -> dict:
        return self.__dict__.copy()

@dataclass
class Session:

    target:      str
    scope:       list[str]             = field(default_factory=list)
    exclude:     list[str]             = field(default_factory=list)
    proxy:       Optional[str]         = None
    verbose:     bool                  = False
    silent:      bool                  = False

    id:          str                   = field(default_factory=lambda: str(uuid.uuid4())[:12])
    started_at:  str                   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]         = None

    findings:    list[Finding]         = field(default_factory=list)
    modules_run: list[str]             = field(default_factory=list)
    modules_failed: list[str]          = field(default_factory=list)
    errors:      list[str]             = field(default_factory=list)
    metadata:    dict[str, Any]        = field(default_factory=dict)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_findings(self, findings: list[Finding]):
        self.findings.extend(findings)

    def finding(
        self,
        module:      str,
        category:    str,
        severity:    str,
        title:       str,
        description: str,
        **kwargs,
    ) -> Finding:
        f = Finding(
            module=module,
            category=category,
            severity=severity,
            title=title,
            description=description,
            target=self.target,
            **kwargs,
        )
        self.add_finding(f)
        return f

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def medium(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "medium"]

    @property
    def low(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "low"]

    @property
    def info(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "info"]

    def by_module(self, module: str) -> list[Finding]:
        return [f for f in self.findings if f.module == module]

    def by_category(self, category: str) -> list[Finding]:
        return [f for f in self.findings if f.category == category]

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def has_critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)

    def mark_done(self, module: str):
        if module not in self.modules_run:
            self.modules_run.append(module)

    def mark_failed(self, module: str, error: str = ""):
        if module not in self.modules_failed:
            self.modules_failed.append(module)
        if error:
            self.errors.append(f"[{module}] {error}")

    def was_run(self, module: str) -> bool:
        return module in self.modules_run

    def set_meta(self, key: str, value: Any):
        self.metadata[key] = value

    def get_meta(self, key: str, default: Any = None) -> Any:
        return self.metadata.get(key, default)

    def update_meta(self, key: str, value: Any):

        existing = self.metadata.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            existing.update(value)
        elif isinstance(existing, list) and isinstance(value, list):
            existing.extend(value)
        else:
            self.metadata[key] = value

    def finish(self):
        self.finished_at = datetime.now(timezone.utc).isoformat()

    def duration(self) -> Optional[float]:
        if not self.finished_at:
            return None
        start = datetime.fromisoformat(self.started_at)
        end   = datetime.fromisoformat(self.finished_at)
        return round((end - start).total_seconds(), 2)

    def summary(self) -> dict:
        return {
            "session_id":     self.id,
            "target":         self.target,
            "started_at":     self.started_at,
            "finished_at":    self.finished_at,
            "duration_s":     self.duration(),
            "modules_run":    self.modules_run,
            "modules_failed": self.modules_failed,
            "findings": {
                "total":    len(self.findings),
                "critical": len(self.critical),
                "high":     len(self.high),
                "medium":   len(self.medium),
                "low":      len(self.low),
                "info":     len(self.info),
            },
            "errors": self.errors,
        }

    def to_dict(self) -> dict:
        d = self.summary()
        d["findings_detail"] = [f.to_dict() for f in self.findings]
        d["metadata"]        = self.metadata
        return d

    def __repr__(self) -> str:
        return (
            f"<Session id={self.id} target={self.target} "
            f"findings={len(self.findings)} "
            f"critical={len(self.critical)}>"
        )

_session: Optional[Session] = None

def init_session(target: str, **kwargs) -> Session:
    global _session
    _session = Session(target=target, **kwargs)
    return _session

def get_session() -> Optional[Session]:
    return _session