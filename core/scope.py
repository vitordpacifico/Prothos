"""Scope guard — enforces engagement scope on every outbound request.

The guard is the first safety rail of Prothos. Recon/scan/exploit traffic is
checked against an allow-list (scope) and a deny-list (exclude) before it
leaves the process. In `lab` mode the guard never blocks (CTF / owned boxes),
but every decision is still recorded so the audit trail stays complete.
"""

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when a target falls outside the authorized scope."""


def _host_of(target: str) -> str:
    if "://" not in target:
        target = f"//{target}"
    return (urlparse(target).hostname or "").lower()


def _as_network(pattern: str) -> Optional[ipaddress._BaseNetwork]:
    try:
        return ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return None


def _as_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _matches(host: str, pattern: str) -> bool:
    """A host matches a pattern by exact value, glob, parent-domain or CIDR."""
    pattern = pattern.strip().lower()
    if not pattern:
        return False

    net = _as_network(pattern)
    if net is not None:
        ip = _as_ip(host)
        return ip is not None and ip in net

    if pattern.startswith("*."):
        suffix = pattern[1:]               # ".example.com"
        return host == pattern[2:] or host.endswith(suffix)

    if fnmatch.fnmatch(host, pattern):
        return True

    # bare domain also covers its subdomains
    return host == pattern or host.endswith("." + pattern)


@dataclass
class ScopeGuard:
    scope:   list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    lab:     bool      = False

    def in_scope(self, target: str) -> bool:
        host = _host_of(target)
        if not host:
            return self.lab
        if any(_matches(host, p) for p in self.exclude):
            return False
        if self.lab:
            return True
        if not self.scope:
            # no scope defined + not lab => fail closed
            return False
        return any(_matches(host, p) for p in self.scope)

    def assert_in_scope(self, target: str):
        if self.in_scope(target):
            return
        host = _host_of(target) or target
        raise ScopeViolation(
            f"'{host}' is outside the authorized scope. "
            f"Add it to the RoE scope, or run with lab mode for owned/CTF targets."
        )


# --- module-level singleton -------------------------------------------------

_guard: Optional[ScopeGuard] = None


def init_guard(scope=None, exclude=None, lab: bool = False) -> ScopeGuard:
    global _guard
    _guard = ScopeGuard(scope=list(scope or []), exclude=list(exclude or []), lab=lab)
    return _guard


def get_guard() -> ScopeGuard:
    """Return the active guard. Defaults to a fail-closed empty guard."""
    global _guard
    if _guard is None:
        _guard = ScopeGuard()
    return _guard


def in_scope(target: str) -> bool:
    return get_guard().in_scope(target)


def assert_in_scope(target: str):
    get_guard().assert_in_scope(target)
