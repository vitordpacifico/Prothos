"""Privilege-escalation enumeration (Linux/Windows).

Runs a battery of local-privesc checks through an `exec_fn` (a command-exec
primitive from cmdi_exploit / shell / c2 beacon) and flags exploitable
conditions: sudo NOPASSWD, dangerous SUID binaries, writable cron/service
paths. With no exec_fn it prints the checklist so an operator can run it
manually. Gated by postex._base.preflight.
"""

import re
from typing import Optional
from postex._base import (
    PostexReport, ExecFn, preflight, display, save, header, console,
)
from core import audit

LINUX_CHECKS: list[tuple[str, str]] = [
    ("whoami_id",         "id"),
    ("sudo_rights",       "sudo -n -l 2>/dev/null"),
    ("kernel",            "uname -a"),
    ("suid_binaries",     "find / -perm -4000 -type f 2>/dev/null"),
    ("capabilities",      "getcap -r / 2>/dev/null"),
    ("crontab",           "cat /etc/crontab 2>/dev/null"),
    ("passwd_perms",      "ls -la /etc/passwd /etc/shadow 2>/dev/null"),
    ("writable_root_dirs","find / -writable -type d 2>/dev/null | grep -E '^/(etc|usr|bin|sbin|opt)' | head"),
]

WINDOWS_CHECKS: list[tuple[str, str]] = [
    ("whoami",            "whoami /all"),
    ("system_info",       "systeminfo"),
    ("unquoted_services", "wmic service get name,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\windows\\\\\" | findstr /i /v \"\\\"\""),
    ("alwaysinstall",     "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"),
    ("stored_creds",      "cmdkey /list"),
]

# SUID paths that are known GTFOBins privesc vectors
GTFO_SUID = {"nmap", "vim", "find", "bash", "more", "less", "nano", "cp", "awk",
             "python", "perl", "ruby", "php", "env", "tar", "zip", "docker"}


def _analyze(report: PostexReport, check: str, output: str):
    out = output.strip()
    if not out:
        report.add(check, "(no output)")
        return

    if check == "sudo_rights":
        if "NOPASSWD" in out:
            report.add(check, "sudo NOPASSWD entries present", "critical", finding=True)
            report.add_loot(f"sudo NOPASSWD: {out[:200]}")
        elif "may run" in out:
            report.add(check, "sudo rights available", "high", finding=True)
        else:
            report.add(check, out[:80])
    elif check == "suid_binaries":
        bins = {p.rsplit("/", 1)[-1] for p in out.split()}
        hits = bins & GTFO_SUID
        if hits:
            report.add(check, f"exploitable SUID: {', '.join(sorted(hits))}", "critical", finding=True)
            report.add_loot(f"GTFOBins SUID: {', '.join(sorted(hits))}")
        else:
            report.add(check, f"{len(bins)} SUID binaries (none known-exploitable)")
    elif check == "passwd_perms":
        if re.search(r"-rw.{6,}.*\spasswd", out) and re.search(r"^-rw-rw|^-rwxrwx", out, re.M):
            report.add(check, "/etc/passwd appears writable", "critical", finding=True)
        else:
            report.add(check, out.splitlines()[0][:80] if out else "-")
    elif check in ("unquoted_services", "alwaysinstall") and out and "0x1" in out or (
            check == "unquoted_services" and out):
        report.add(check, "potential privesc vector", "high", finding=True)
        report.add_loot(f"{check}: {out[:150]}")
    elif check == "whoami_id" or check == "whoami":
        report.add(check, out[:80])
        report.add_loot(f"identity: {out.splitlines()[0][:80]}")
    else:
        report.add(check, out.splitlines()[0][:80] if out else "-")


def run_privesc_enum(
    target:        str,
    exec_fn:       Optional[ExecFn] = None,
    os_type:       str              = "linux",
    allow_postex:  bool             = False,
    lab:           bool             = False,
    save_json:     Optional[str]    = None,
    **_,
) -> PostexReport:
    header("privesc_enum", target, "live" if exec_fn else "checklist")
    refusal = preflight("privesc_enum", target, allow_postex, lab)
    if refusal is not None:
        return refusal

    report = PostexReport(module="privesc_enum", target=target)
    checks = WINDOWS_CHECKS if os_type.lower().startswith("win") else LINUX_CHECKS

    if exec_fn is None:
        report.mode = "checklist"
        console.print("[dim]    No exec_fn — emitting checklist (run on the host):[/dim]")
        for name, cmd in checks:
            report.add(name, cmd)
        return _finish(report, save_json)

    report.mode = "live"
    for name, cmd in checks:
        audit.audit("postex_cmd", module="privesc_enum", target=target, payload=cmd, severity="high")
        try:
            output = exec_fn(cmd) or ""
        except Exception as e:
            report.errors.append(f"{name}: {e}")
            continue
        _analyze(report, name, output)

    return _finish(report, save_json)


def _finish(report: PostexReport, save_json):
    report.finish()
    display(report)
    save(report, save_json)
    return report
