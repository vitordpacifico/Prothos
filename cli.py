import sys
import inspect
from datetime import datetime, timezone
from urllib.parse import urlparse
from rich.console import Console

from utils.banner import show_banner
from core.module_loader import autodiscover
from core.session import Session, init_session, get_session

console = Console()

R   = "\033[91m"
G   = "\033[92m"
Y   = "\033[93m"
C   = "\033[96m"
W   = "\033[97m"
DIM = "\033[2m"
RESET = "\033[0m"

DOMAIN_ARG = {
    "subdomain_bruteforce", "passive_subdomains", "dns_recon", "whois_lookup",
    "certificate_enum", "cloud_enum", "email_harvester", "github_recon",
    "shodan_query", "social_recon",
}

CATEGORY_LABEL = {
    "recon":       "RECON",
    "enumeration": "ENUMERATION",
    "vulnscan":    "VULN SCAN",
    "evasion":     "EVASION",
    "postex":      "POST-EX (audit)",
}

CATEGORY_ORDER = ["recon", "enumeration", "vulnscan", "evasion", "postex"]

VALID_SEV = {"critical", "high", "medium", "low", "info"}


def _hostname(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return parsed.hostname or target


def _filter_kwargs(fn, **kwargs) -> dict:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return {}
    return {k: v for k, v in kwargs.items() if k in params}


def _safe_call(fn, primary, **kwargs):
    accepted = _filter_kwargs(fn, **kwargs)
    try:
        return fn(primary, **accepted)
    except TypeError:
        try:
            return fn(primary)
        except Exception as e:
            console.print(f"{R}[!] Module call failed: {e}{RESET}")
            return None
    except KeyboardInterrupt:
        console.print(f"{Y}[!] Module interrupted.{RESET}")
        return None
    except Exception as e:
        console.print(f"{R}[!] Module error: {e}{RESET}")
        return None


def _ingest(session: Session, module: str, category: str, report) -> int:
    if report is None:
        return 0
    try:
        d = report.to_dict() if hasattr(report, "to_dict") else (report if isinstance(report, dict) else {})
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
        title = (f.get("title") or f.get("issue") or f.get("cve") or f.get("technique")
                 or f.get("engine") or f.get("kind") or f.get("service") or module)
        try:
            session.finding(
                module=module,
                category=category,
                severity=sev,
                title=str(title)[:200],
                description=str(f.get("description") or f.get("detail") or f.get("evidence") or title)[:1000],
                url=f.get("url") or f.get("subdomain") or f.get("target"),
                param=f.get("param"),
                payload=f.get("payload"),
                evidence=str(f.get("evidence") or "")[:1000],
                cve=f.get("cve"),
            )
            count += 1
        except Exception:
            continue
    if count:
        session.mark_done(module)
    return count


def _ensure_session(target: str) -> Session:
    sess = get_session()
    if sess is None or sess.target != target:
        sess = init_session(target=target)
    return sess


def _prompt(label: str) -> str:
    try:
        return input(f"{G}{label}{RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        return ""


def _prompt_target(label: str = "Target URL > ") -> str:
    while True:
        t = _prompt(label)
        if t:
            return t
        console.print(f"{R}[!] Target cannot be empty.{RESET}")


def _run_module(info, target: str):
    primary = _hostname(target) if info.name in DOMAIN_ARG else target
    console.print(f"\n{C}[*] Running {info.category}/{info.name}{RESET}")
    report = _safe_call(info.fn, primary, proxy=get_session().proxy if get_session() else None)
    sess = _ensure_session(target)
    n = _ingest(sess, info.name, info.category, report)
    if n:
        console.print(f"{DIM}    [+] {n} finding(s) added to session {sess.id}{RESET}")


def _submenu_subdomain(loader, target: str):
    domain = _hostname(target)
    console.print(f"\n{W}Subdomain:{RESET} [1] Bruteforce  [2] Passive  [3] Engine (both)")
    choice = _prompt("subdomain> ")
    sess = _ensure_session(target)
    if choice == "1" and loader.get("subdomain_bruteforce"):
        _ingest(sess, "subdomain_bruteforce", "recon",
                _safe_call(loader.get("subdomain_bruteforce").fn, domain, proxy=sess.proxy))
    elif choice == "2" and loader.get("passive_subdomains"):
        _ingest(sess, "passive_subdomains", "recon",
                _safe_call(loader.get("passive_subdomains").fn, domain))
    elif choice == "3":
        try:
            import engines.subbrute_engine as eng
            fn = next((getattr(eng, a) for a in dir(eng) if a.startswith("run_")), None)
            if fn:
                _ingest(sess, "subbrute_engine", "recon", _safe_call(fn, domain, proxy=sess.proxy))
            else:
                console.print(f"{R}[!] No run_* entry in subbrute_engine{RESET}")
        except ImportError:
            console.print(f"{R}[!] subbrute_engine not available{RESET}")
    else:
        console.print(f"{R}[!] Invalid option.{RESET}")


def _submenu_kw(loader, target: str, name: str, category: str, label: str, options: dict):
    info = loader.get(name)
    if not info:
        console.print(f"{R}[!] {name} not available.{RESET}")
        return
    console.print(f"\n{W}{label}{RESET}")
    for k, (desc, _) in options.items():
        console.print(f"  [{k}] {desc}")
    choice = _prompt(f"{name}> ")
    if choice not in options:
        console.print(f"{R}[!] Invalid option.{RESET}")
        return
    _, kwargs = options[choice]
    primary = _hostname(target) if name in DOMAIN_ARG else target
    sess = _ensure_session(target)
    if callable(kwargs):
        kwargs = kwargs()
    _ingest(sess, name, category, _safe_call(info.fn, primary, proxy=sess.proxy, **kwargs))


def _menu_scan(loader, target: str):
    while True:
        console.print(f"\n{W}=== MODULES ==={RESET}  {DIM}target: {target}{RESET}")
        entries = []
        idx = 1
        for cat in CATEGORY_ORDER:
            mods = loader.get_by_category(cat)
            if not mods:
                continue
            console.print(f"\n{R}[ {CATEGORY_LABEL.get(cat, cat.upper())} ]{RESET}")
            for m in sorted(mods, key=lambda x: x.name):
                entries.append(m)
                console.print(f"  {W}[{idx}]{RESET} {m.name}")
                idx += 1

        console.print(f"\n{R}[ FUZZING ]{RESET}")
        console.print(f"  {W}[P]{RESET} param_fuzzer    {W}[E]{RESET} method_enum")
        console.print(f"\n  {W}[A]{RESET} Run All (recon + enum + vulnscan)    {DIM}[0] Back{RESET}")

        choice = _prompt("module> ").lower()
        if choice == "0":
            return
        elif choice == "a":
            _run_all(loader, target)
        elif choice == "p":
            params = [p.strip() for p in _prompt("Params (comma separated) > ").split(",") if p.strip()]
            try:
                from fuzzing.param_fuzzer import fuzz_params
                sess = _ensure_session(target)
                _ingest(sess, "param_fuzzer", "fuzzing", fuzz_params(target, params, proxy=sess.proxy))
            except Exception as e:
                console.print(f"{R}[!] {e}{RESET}")
        elif choice == "e":
            try:
                from fuzzing.method_enum import enum_methods
                sess = _ensure_session(target)
                _ingest(sess, "method_enum", "fuzzing", enum_methods(target, proxy=sess.proxy))
            except Exception as e:
                console.print(f"{R}[!] {e}{RESET}")
        elif choice.isdigit() and 1 <= int(choice) <= len(entries):
            info = entries[int(choice) - 1]
            if info.name == "social_recon":
                _submenu_kw(loader, target, "social_recon", "recon", "Social Recon:",
                            {"1": ("Domain Recon", {"mode": "domain"}),
                             "2": ("Person Recon", {"mode": "person"})})
            elif info.name == "port_scan":
                _submenu_kw(loader, target, "port_scan", "enumeration", "Port Scan:",
                            {"1": ("Common", {"mode": "common"}),
                             "2": ("Web", {"mode": "web"}),
                             "3": ("DB", {"mode": "db"}),
                             "4": ("Full", {"mode": "full"})})
            elif info.name == "cloud_enum":
                _submenu_kw(loader, target, "cloud_enum", "recon", "Cloud Enum:",
                            {"1": ("Auto-detect", {}),
                             "2": ("Custom names", lambda: {"names": [n.strip() for n in _prompt("Names (comma) > ").split(",") if n.strip()]})})
            elif info.name == "email_harvester":
                _submenu_kw(loader, target, "email_harvester", "recon", "Email Harvester:",
                            {"1": ("Harvest only", {}),
                             "2": ("Harvest + HIBP", {"hibp": True}),
                             "3": ("Harvest + Spray list", {"spray": True})})
            else:
                _run_module(info, target)
        else:
            console.print(f"{R}[!] Invalid option.{RESET}")


def _run_all(loader, target: str):
    console.print(f"\n{Y}[*] Full pipeline on {W}{target}{RESET}")
    sess = _ensure_session(target)
    for cat in ("recon", "enumeration", "vulnscan"):
        for m in sorted(loader.get_by_category(cat), key=lambda x: x.name):
            primary = _hostname(target) if m.name in DOMAIN_ARG else target
            console.print(f"{C}[>] {m.category}/{m.name}{RESET}")
            report = _safe_call(m.fn, primary, proxy=sess.proxy)
            _ingest(sess, m.name, m.category, report)
    console.print(f"\n{G}[OK] Pipeline complete — {len(sess.findings)} findings in session {sess.id}{RESET}")


def _menu_oob():
    console.print(f"\n{W}=== OOB / CONFIRMATION ==={RESET}")
    console.print(f"  {W}[1]{RESET} HTTP logger   {W}[2]{RESET} DNS logger   {W}[3]{RESET} Interactsh   {DIM}[0] Back{RESET}")
    choice = _prompt("oob> ")
    if choice == "1":
        from c2.http_log import run_http_log
        port = _prompt("Port [8080] > ") or "8080"
        dur = _prompt("Duration s [120] > ") or "120"
        run_http_log(port=int(port), duration=int(dur))
    elif choice == "2":
        from c2.dns_log import run_dns_log
        domain = _prompt_target("OOB domain > ")
        port = _prompt("UDP port [5353] > ") or "5353"
        dur = _prompt("Duration s [120] > ") or "120"
        run_dns_log(domain, listen_port=int(port), duration=int(dur))
    elif choice == "3":
        from c2.interactsh_client import run_interactsh_client
        dur = _prompt("Duration s [120] > ") or "120"
        run_interactsh_client(duration=int(dur))


def _menu_tools():
    console.print(f"\n{W}=== TOOLS ==={RESET}")
    console.print(f"  {W}[1]{RESET} Encoder (payload)   {DIM}[0] Back{RESET}")
    choice = _prompt("tools> ")
    if choice == "1":
        from evasion.encoder import run_encoder
        payload = _prompt("Payload > ")
        if payload:
            run_encoder(payload)


def _menu_output():
    sess = get_session()
    if sess is None or not sess.findings:
        console.print(f"{Y}[!] No session findings yet. Run modules first.{RESET}")
        return
    sess.finish()
    console.print(f"\n{W}=== OUTPUT ==={RESET}  {DIM}{len(sess.findings)} findings{RESET}")
    console.print(f"  {W}[1]{RESET} JSON  {W}[2]{RESET} HTML  {W}[3]{RESET} Markdown  "
                  f"{W}[4]{RESET} PDF  {W}[5]{RESET} SARIF  {W}[6]{RESET} Burp XML   {DIM}[0] Back{RESET}")
    choice = _prompt("output> ")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = f"output/session_{ts}"
    try:
        if choice == "1":
            from output.json_exporter import export_json
            export_json(sess.to_dict(), f"{base}.json")
        elif choice == "2":
            from output.html_exporter import export_html
            data = sess.to_dict(); data["target"] = sess.target
            export_html(data, f"{base}.html")
        elif choice == "3":
            from output.markdown_report import run_markdown_report
            run_markdown_report(sess, f"{base}.md")
        elif choice == "4":
            from output.pdf_report import run_pdf_report
            run_pdf_report(sess, f"{base}.pdf", tester=_prompt("Tester > ") or "Prothos")
        elif choice == "5":
            from output.sarif_export import run_sarif_export
            run_sarif_export(sess, f"{base}.sarif")
        elif choice == "6":
            from integrations.burp_export import run_burp_export
            run_burp_export(sess, f"{base}.xml")
    except Exception as e:
        console.print(f"{R}[!] Export failed: {e}{RESET}")


def _menu_session():
    console.print(f"\n{W}=== SESSION ==={RESET}")
    console.print(f"  {W}[1]{RESET} Show  {W}[2]{RESET} Save  {W}[3]{RESET} Load   {DIM}[0] Back{RESET}")
    choice = _prompt("session> ")
    sess = get_session()
    if choice == "1":
        if sess:
            console.print(sess.summary())
        else:
            console.print(f"{Y}[!] No active session.{RESET}")
    elif choice == "2":
        if not sess:
            console.print(f"{Y}[!] No active session.{RESET}")
            return
        path = _prompt("Save path [output/session.json] > ") or "output/session.json"
        try:
            from output.json_exporter import export_json
            sess.finish()
            export_json(sess.to_dict(), path)
        except Exception as e:
            console.print(f"{R}[!] {e}{RESET}")
    elif choice == "3":
        path = _prompt("Load path > ")
        if not path:
            return
        try:
            from output.json_exporter import load_json
            data = load_json(path)
            target = data.get("target", "unknown")
            sess = init_session(target=target)
            for f in data.get("findings_detail", []):
                sev = f.get("severity", "info")
                if sev not in VALID_SEV:
                    sev = "info"
                sess.finding(module=f.get("module", "loaded"), category=f.get("category", "recon"),
                             severity=sev, title=str(f.get("title", "finding")),
                             description=str(f.get("description", "")),
                             url=f.get("url"), param=f.get("param"), payload=f.get("payload"),
                             evidence=str(f.get("evidence", "")), cve=f.get("cve"))
            console.print(f"{G}[OK] Loaded {len(sess.findings)} findings for {target}{RESET}")
        except Exception as e:
            console.print(f"{R}[!] Load failed: {e}{RESET}")


MAIN_MENU = f"""
  {W}[1]{RESET} Scan Modules        {DIM}recon / enum / vulnscan / evasion / postex{RESET}
  {W}[2]{RESET} OOB / Confirmation  {DIM}http / dns / interactsh listeners{RESET}
  {W}[3]{RESET} Tools               {DIM}encoder{RESET}
  {W}[4]{RESET} Output              {DIM}json / html / markdown / pdf / sarif / burp{RESET}
  {W}[5]{RESET} Session             {DIM}show / save / load{RESET}
  {DIM}[0] Exit{RESET}
"""


def start_cli():
    show_banner()
    loader = autodiscover()
    summary = loader.summary()
    console.print(f"{DIM}    Loaded {summary['total']} modules: "
                  f"{', '.join(f'{k}={v}' for k, v in summary['categories'].items())}{RESET}")

    target = None
    while True:
        console.print(MAIN_MENU)
        if target:
            console.print(f"{DIM}  active target: {target}{RESET}")
        try:
            option = input(f"{W}prothos{R}>{RESET} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print(f"\n{R}[!] Exiting Prothos...{RESET}")
            sys.exit(0)

        if option == "0":
            console.print(f"\n{DIM}Exiting Prothos...{RESET}\n")
            break
        elif option == "1":
            target = target or _prompt_target()
            _ensure_session(target)
            _menu_scan(loader, target)
        elif option == "2":
            _menu_oob()
        elif option == "3":
            _menu_tools()
        elif option == "4":
            _menu_output()
        elif option == "5":
            _menu_session()
        elif option in ("t", "target"):
            target = _prompt_target()
            _ensure_session(target)
        else:
            console.print(f"{R}[!] Invalid option '{option}'.{RESET}")
