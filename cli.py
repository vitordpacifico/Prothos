import sys
import inspect
from datetime import datetime, timezone
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns

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
    "recon":        "RECON",
    "enumeration":  "ENUMERATION",
    "vulnscan":     "VULN SCAN",
    "exploitation": "EXPLOITATION",
    "evasion":      "EVASION",
    "postex":       "POST-EX",
}

CATEGORY_ORDER = ["recon", "enumeration", "vulnscan", "exploitation", "evasion", "postex"]

# modules that require an explicit consent gate (exploitation / live post-ex)
GATED_EXPLOIT = {"sqli_exploit", "ssti_exploit", "cmdi_exploit", "lfi_exploit", "ssrf_exploit"}
GATED_POSTEX  = {"privesc_enum", "loot_collector"}

# lab mode disables the scope guard for owned/CTF targets (audit stays on)
_LAB = False

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
            console.print(f"[red][!] Module call failed: {e}[/red]")
            return None
    except KeyboardInterrupt:
        console.print("[yellow][!] Module interrupted.[/yellow]")
        return None
    except Exception as e:
        console.print(f"[red][!] Module error: {e}[/red]")
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
        console.print(label, end="")
        return input().strip()
    except (KeyboardInterrupt, EOFError):
        return ""


def _prompt_target(label: str = "[green]target >[/green] ") -> str:
    while True:
        t = _prompt(label)
        if t and not t.lower().startswith(("c:", "(.venv", "python ", "module")):
            return t
        console.print("[red][!] Informe uma URL/host valido (ex: https://alvo.com)[/red]")


def _consent(action: str) -> bool:
    """Active-action gate. Lab mode auto-consents; otherwise require typed yes."""
    if _LAB:
        console.print(f"[dim]    [lab] {action} auto-consented (scope guard off)[/dim]")
        return True
    console.print(f"[bold yellow][!] {action} is an ACTIVE action against the target.[/bold yellow]")
    console.print("[dim]    Only proceed on systems you are authorized to test (RoE).[/dim]")
    return _prompt("[bold red]type 'yes' to authorize >[/bold red] ").lower() == "yes"


def _run_module(info, target: str):
    primary = _hostname(target) if info.name in DOMAIN_ARG else target
    sess = _ensure_session(target)
    extra = {}

    if info.name in GATED_EXPLOIT:
        if not _consent(f"exploitation/{info.name}"):
            console.print("[yellow][!] Not authorized — skipping.[/yellow]")
            return
        param = _prompt("[green]param (blank=auto) >[/green] ").strip()
        extra = {"allow_exploit": True, "lab": _LAB}
        if param:
            extra["param"] = param
    elif info.name in GATED_POSTEX:
        if not _consent(f"postex/{info.name}"):
            console.print("[yellow][!] Not authorized — skipping.[/yellow]")
            return
        extra = {"allow_postex": True, "lab": _LAB}

    console.print(f"\n[cyan][*] Running {info.category}/{info.name}[/cyan]")
    report = _safe_call(info.fn, primary, proxy=sess.proxy, **extra)
    n = _ingest(sess, info.name, info.category, report)
    if n:
        console.print(f"[dim]    [+] {n} finding(s) added to session {sess.id}[/dim]")


def _submenu_subdomain(loader, target: str):
    domain = _hostname(target)
    console.print("\n[bold white]Subdomain:[/bold white] [1] Bruteforce  [2] Passive  [3] Engine (both)")
    choice = _prompt("[green]subdomain >[/green] ")
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
                console.print("[red][!] No run_* entry in subbrute_engine[/red]")
        except ImportError:
            console.print("[red][!] subbrute_engine not available[/red]")
    else:
        console.print("[red][!] Opcao invalida.[/red]")


def _submenu_kw(loader, target: str, name: str, category: str, label: str, options: dict):
    info = loader.get(name)
    if not info:
        console.print(f"[red][!] {name} not available.[/red]")
        return
    console.print(f"\n[bold white]{label}[/bold white]")
    for k, (desc, _) in options.items():
        console.print(f"  [bold white][{k}][/bold white] {desc}")
    choice = _prompt(f"[green]{name} >[/green] ")
    if choice not in options:
        console.print("[red][!] Opcao invalida.[/red]")
        return
    _, kwargs = options[choice]
    primary = _hostname(target) if name in DOMAIN_ARG else target
    sess = _ensure_session(target)
    if callable(kwargs):
        kwargs = kwargs()
    _ingest(sess, name, category, _safe_call(info.fn, primary, proxy=sess.proxy, **kwargs))


def _render_modules(loader) -> list:
    entries = []
    tables = []
    idx = 1
    for cat in CATEGORY_ORDER:
        mods = sorted(loader.get_by_category(cat), key=lambda x: x.name)
        if not mods:
            continue
        t = Table(title=CATEGORY_LABEL.get(cat, cat.upper()), title_style="bold red",
                  show_header=False, box=None, padding=(0, 1, 0, 0))
        t.add_column(justify="right", style="bold red", no_wrap=True)
        t.add_column(style="white", no_wrap=True)
        for m in mods:
            entries.append(m)
            t.add_row(str(idx), m.name)
            idx += 1
        tables.append(t)

    console.print(Columns(tables, padding=(0, 3), expand=False))
    console.print(
        "  [bold white]P[/bold white] param_fuzzer    "
        "[bold white]E[/bold white] method_enum    "
        "[bold white]A[/bold white] run all    "
        "[bold white]L[/bold white] list again    "
        "[dim]0 back[/dim]"
    )
    return entries


def _menu_scan(loader, target: str):
    console.print(Panel(f"[bold white]{target}[/bold white]",
                        title="[bold red]Modules[/bold red]", border_style="red", expand=False))
    entries = _render_modules(loader)

    while True:
        choice = _prompt("[green]module >[/green] ").lower()

        if choice == "0":
            return
        elif choice in ("l", "list"):
            entries = _render_modules(loader)
            continue
        elif choice == "":
            continue
        elif choice == "a":
            _run_all(loader, target)
        elif choice == "p":
            params = [p.strip() for p in _prompt("[green]params (comma) >[/green] ").split(",") if p.strip()]
            try:
                from fuzzing.param_fuzzer import fuzz_params
                sess = _ensure_session(target)
                _ingest(sess, "param_fuzzer", "fuzzing", fuzz_params(target, params, proxy=sess.proxy))
            except Exception as e:
                console.print(f"[red][!] {e}[/red]")
        elif choice == "e":
            try:
                from fuzzing.method_enum import enum_methods
                sess = _ensure_session(target)
                _ingest(sess, "method_enum", "fuzzing", enum_methods(target, proxy=sess.proxy))
            except Exception as e:
                console.print(f"[red][!] {e}[/red]")
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
                             "2": ("Custom names", lambda: {"names": [n.strip() for n in _prompt("[green]names (comma) >[/green] ").split(",") if n.strip()]})})
            elif info.name == "email_harvester":
                _submenu_kw(loader, target, "email_harvester", "recon", "Email Harvester:",
                            {"1": ("Harvest only", {}),
                             "2": ("Harvest + HIBP", {"hibp": True}),
                             "3": ("Harvest + Spray list", {"spray": True})})
            else:
                _run_module(info, target)
        else:
            console.print("[red][!] Opcao invalida.[/red] [dim](numero do modulo, ou L=listar, 0=voltar)[/dim]")
            continue

        console.print("\n[dim]--- escolha outro modulo (L lista de novo, 0 volta) ---[/dim]")


def _run_all(loader, target: str):
    console.print(f"\n[yellow][*] Full pipeline on [bold white]{target}[/bold white][/yellow]")
    sess = _ensure_session(target)
    for cat in ("recon", "enumeration", "vulnscan"):
        for m in sorted(loader.get_by_category(cat), key=lambda x: x.name):
            primary = _hostname(target) if m.name in DOMAIN_ARG else target
            console.print(f"[cyan][>] {m.category}/{m.name}[/cyan]")
            report = _safe_call(m.fn, primary, proxy=sess.proxy)
            _ingest(sess, m.name, m.category, report)
    console.print(f"\n[green][OK] Pipeline complete — {len(sess.findings)} findings in session {sess.id}[/green]")


def _menu_oob():
    console.print(Panel("[bold white][1][/bold white] HTTP logger    "
                        "[bold white][2][/bold white] DNS logger    "
                        "[bold white][3][/bold white] Interactsh    [dim]0 back[/dim]",
                        title="[bold red]OOB / Confirmation[/bold red]", border_style="red", expand=False))
    choice = _prompt("[green]oob >[/green] ")
    if choice == "1":
        from c2.http_log import run_http_log
        port = _prompt("[green]port [8080] >[/green] ") or "8080"
        dur = _prompt("[green]duration s [120] >[/green] ") or "120"
        run_http_log(port=int(port), duration=int(dur))
    elif choice == "2":
        from c2.dns_log import run_dns_log
        domain = _prompt_target("[green]OOB domain >[/green] ")
        port = _prompt("[green]UDP port [5353] >[/green] ") or "5353"
        dur = _prompt("[green]duration s [120] >[/green] ") or "120"
        run_dns_log(domain, listen_port=int(port), duration=int(dur))
    elif choice == "3":
        from c2.interactsh_client import run_interactsh_client
        dur = _prompt("[green]duration s [120] >[/green] ") or "120"
        run_interactsh_client(duration=int(dur))


def _menu_tools():
    console.print(Panel("[bold white][1][/bold white] Encoder (payload)    [dim]0 back[/dim]",
                        title="[bold red]Tools[/bold red]", border_style="red", expand=False))
    choice = _prompt("[green]tools >[/green] ")
    if choice == "1":
        from evasion.encoder import run_encoder
        payload = _prompt("[green]payload >[/green] ")
        if payload:
            run_encoder(payload)


def _menu_output():
    sess = get_session()
    if sess is None or not sess.findings:
        console.print("[yellow][!] Nenhum finding na sessao ainda. Rode modulos primeiro.[/yellow]")
        return
    sess.finish()
    console.print(Panel(
        "[bold white][1][/bold white] JSON   [bold white][2][/bold white] HTML   "
        "[bold white][3][/bold white] Markdown   [bold white][4][/bold white] PDF   "
        "[bold white][5][/bold white] SARIF   [bold white][6][/bold white] Burp XML   [dim]0 back[/dim]",
        title=f"[bold red]Output[/bold red]  [dim]{len(sess.findings)} findings[/dim]",
        border_style="red", expand=False))
    choice = _prompt("[green]output >[/green] ")
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
            run_pdf_report(sess, f"{base}.pdf", tester=_prompt("[green]tester >[/green] ") or "Prothos")
        elif choice == "5":
            from output.sarif_export import run_sarif_export
            run_sarif_export(sess, f"{base}.sarif")
        elif choice == "6":
            from integrations.burp_export import run_burp_export
            run_burp_export(sess, f"{base}.xml")
    except Exception as e:
        console.print(f"[red][!] Export failed: {e}[/red]")


def _menu_session():
    console.print(Panel("[bold white][1][/bold white] Show   [bold white][2][/bold white] Save   "
                        "[bold white][3][/bold white] Load   [dim]0 back[/dim]",
                        title="[bold red]Session[/bold red]", border_style="red", expand=False))
    choice = _prompt("[green]session >[/green] ")
    sess = get_session()
    if choice == "1":
        if sess:
            console.print(sess.summary())
        else:
            console.print("[yellow][!] Nenhuma sessao ativa.[/yellow]")
    elif choice == "2":
        if not sess:
            console.print("[yellow][!] Nenhuma sessao ativa.[/yellow]")
            return
        path = _prompt("[green]save path [output/session.json] >[/green] ") or "output/session.json"
        try:
            from output.json_exporter import export_json
            sess.finish()
            export_json(sess.to_dict(), path)
        except Exception as e:
            console.print(f"[red][!] {e}[/red]")
    elif choice == "3":
        path = _prompt("[green]load path >[/green] ")
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
            console.print(f"[green][OK] Loaded {len(sess.findings)} findings for {target}[/green]")
        except Exception as e:
            console.print(f"[red][!] Load failed: {e}[/red]")


def _run_threat_model(target: str):
    sess = _ensure_session(target)
    if not sess.findings:
        console.print("[yellow][!] No findings yet — run recon/vulnscan first.[/yellow]")
        return
    try:
        from core.threat_model import run_threat_model
        run_threat_model(sess)
    except Exception as e:
        console.print(f"[red][!] Threat model failed: {e}[/red]")


def _menu_postengage():
    console.print(Panel(
        "[bold white][1][/bold white] Cleanup report (artifacts)   "
        "[bold white][2][/bold white] Retest / session diff   [dim]0 back[/dim]",
        title="[bold red]Post-Engagement[/bold red]", border_style="red", expand=False))
    choice = _prompt("[green]post-eng >[/green] ")
    if choice == "1":
        from core.artifacts import run_cleanup_report
        sess = get_session()
        run_cleanup_report(session=sess.id if sess else "session")
    elif choice == "2":
        prev = _prompt("[green]previous session json >[/green] ").strip()
        if not prev:
            return
        from core.retest import run_retest
        result = run_retest(prev, get_session())
        if _prompt("[green]write markdown report? [y/N] >[/green] ").lower() == "y":
            from output.retest_report import run_retest_report
            sess = get_session()
            run_retest_report(result, "output/retest.md", target=sess.target if sess else "")


def _scope_to_target(target: str):
    """Scope the guard to the typed target's host so recon works, while still
    fail-closing on anything outside it. Lab mode leaves the guard disabled."""
    if _LAB:
        return
    from core.scope import init_guard
    host = _hostname(target)
    init_guard(scope=[host] if host else [], exclude=[], lab=False)


def _toggle_lab():
    global _LAB
    _LAB = not _LAB
    from core.roe import init_roe, lab_roe, RoE
    if _LAB:
        init_roe(lab_roe())
        console.print("[bold yellow][lab] LAB MODE ON — scope guard disabled "
                      "(use only on owned/CTF targets). Audit stays on.[/bold yellow]")
    else:
        init_roe(RoE())
        console.print("[green][lab] Lab mode OFF — scope guard re-enabled (fail-closed).[/green]")


def _main_menu(target):
    rows = [
        ("1", "Scan Modules", "recon / enum / vulnscan / exploitation / postex"),
        ("2", "OOB / Confirm", "http / dns / interactsh listeners"),
        ("3", "Tools", "encoder"),
        ("4", "Output", "json / html / markdown / pdf / sarif / burp"),
        ("5", "Session", "show / save / load"),
        ("6", "Threat Model", "prioritized attack plan from findings"),
        ("7", "Post-Engagement", "cleanup report / retest diff"),
        ("L", "Lab mode", f"scope guard {'OFF' if _LAB else 'ON'} (CTF/owned)"),
        ("T", "Set target", "trocar o alvo ativo"),
        ("0", "Exit", ""),
    ]
    t = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    t.add_column(style="bold red", justify="right")
    t.add_column(style="bold white")
    t.add_column(style="dim")
    for k, name, desc in rows:
        t.add_row(k, name, desc)
    subtitle = f"[dim]target: {target}[/dim]" if target else "[dim]no target set[/dim]"
    console.print(Panel(t, title="[bold red]PROTHOS[/bold red]", subtitle=subtitle,
                        border_style="red", expand=False))


def start_cli():
    show_banner()
    from core.audit import init_audit
    sess0 = get_session()
    init_audit(sess0.id if sess0 else "session")
    loader = autodiscover()
    summary = loader.summary()
    console.print(f"[dim]    Loaded {summary['total']} modules: "
                  f"{', '.join(f'{k}={v}' for k, v in summary['categories'].items())}[/dim]")

    target = None
    while True:
        _main_menu(target)
        option = _prompt("[bold white]prothos[/bold white][red]>[/red] ").lower()

        if option == "0":
            console.print("\n[dim]Exiting Prothos...[/dim]\n")
            break
        elif option == "1":
            target = target or _prompt_target()
            _ensure_session(target)
            _scope_to_target(target)
            _menu_scan(loader, target)
        elif option == "2":
            _menu_oob()
        elif option == "3":
            _menu_tools()
        elif option == "4":
            _menu_output()
        elif option == "5":
            _menu_session()
        elif option == "6":
            target = target or _prompt_target()
            _run_threat_model(target)
        elif option == "7":
            _menu_postengage()
        elif option in ("l", "lab"):
            _toggle_lab()
        elif option in ("t", "target"):
            target = _prompt_target()
            _ensure_session(target)
            _scope_to_target(target)
        elif option == "":
            continue
        else:
            console.print(f"[red][!] Opcao invalida '{option}'.[/red]")
