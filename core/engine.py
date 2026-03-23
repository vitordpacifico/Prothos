import asyncio
import traceback
from typing import Optional, Callable
from rich.console import Console
from rich.panel import Panel
from core.session import Session, init_session, get_session
from core.output_manager import OutputManager, create_output_manager

console = Console()

class PipelineStep:
    def __init__(
        self,
        name:       str,
        fn:         Callable,
        category:   str          = "recon",
        enabled:    bool         = True,
        required:   bool         = False,
        depends_on: list[str]    = None,
    ):
        self.name       = name
        self.fn         = fn
        self.category   = category
        self.enabled    = enabled
        self.required   = required
        self.depends_on = depends_on or []

class Engine:
    CATEGORY_ORDER = [
        "recon",
        "enumeration",
        "osint",
        "vulnscan",
        "evasion",
        "exploitation",
        "postex",
    ]

    def __init__(
        self,
        target:     str,
        scope:      list[str]      = None,
        exclude:    list[str]      = None,
        proxy:      Optional[str]  = None,
        output_dir: str            = "output",
        verbose:    bool           = False,
        silent:     bool           = False,
        json:       bool           = True,
        html:       bool           = True,
        stop_on_critical: bool     = False,
    ):
        self.target           = target
        self.stop_on_critical = stop_on_critical

        self.session = init_session(
            target=target,
            scope=scope or [],
            exclude=exclude or [],
            proxy=proxy,
            verbose=verbose,
            silent=silent,
        )

        self.output = create_output_manager(
            session=self.session,
            output_dir=output_dir,
            json=json,
            html=html,
            silent=silent,
        )

        self._steps: list[PipelineStep] = []

    def add_step(
        self,
        name:       str,
        fn:         Callable,
        category:   str       = "recon",
        enabled:    bool      = True,
        required:   bool      = False,
        depends_on: list[str] = None,
    ):
        step = PipelineStep(
            name=name,
            fn=fn,
            category=category,
            enabled=enabled,
            required=required,
            depends_on=depends_on or [],
        )
        self._steps.append(step)

    def disable(self, *names: str):
        for step in self._steps:
            if step.name in names:
                step.enabled = False

    def enable(self, *names: str):
        for step in self._steps:
            if step.name in names:
                step.enabled = True

    def only(self, *names: str):
        for step in self._steps:
            step.enabled = step.name in names

    def _resolve_order(self) -> list[PipelineStep]:
        ordered = []
        for cat in self.CATEGORY_ORDER:
            cat_steps = [s for s in self._steps if s.category == cat and s.enabled]
            ordered.extend(cat_steps)
        uncategorized = [
            s for s in self._steps
            if s.category not in self.CATEGORY_ORDER and s.enabled
        ]
        ordered.extend(uncategorized)
        return ordered

    def _check_dependencies(self, step: PipelineStep) -> bool:
        for dep in step.depends_on:
            if not self.session.was_run(dep):
                console.print(
                    f"[yellow][!] Skipping '{step.name}' — "
                    f"dependency '{dep}' was not run.[/yellow]"
                )
                return False
        return True

    def _run_step(self, step: PipelineStep):
        if not self._check_dependencies(step):
            return

        self.output.print_module_start(step.name, self.target)

        try:
            result = step.fn(self.session)

            findings_before = len(self.session.findings)
            self.session.mark_done(step.name)
            findings_after  = len(self.session.findings)
            new_findings    = findings_after - findings_before

            self.output.print_module_done(step.name, new_findings)

            if self.stop_on_critical and self.session.has_critical():
                console.print(
                    f"\n[bold red][!] Critical finding detected — "
                    f"stopping pipeline.[/bold red]"
                )
                raise StopIteration

            return result

        except StopIteration:
            raise
        except KeyboardInterrupt:
            console.print(f"\n[yellow][!] {step.name} interrupted.[/yellow]")
            self.session.mark_failed(step.name, "interrupted by user")
        except Exception as e:
            error = str(e)
            self.output.print_module_error(step.name, error)
            self.session.mark_failed(step.name, error)
            if self.session.verbose:
                console.print(f"[dim]{traceback.format_exc()}[/dim]")
            if step.required:
                raise RuntimeError(
                    f"Required module '{step.name}' failed: {error}"
                ) from e

    def run(self):
        steps = self._resolve_order()

        if not steps:
            console.print("[yellow][!] No modules enabled. Nothing to run.[/yellow]")
            return

        console.print(Panel(
            f"[bold white]{self.target}[/bold white]  "
            f"[dim]modules:[/dim] {len(steps)}  "
            f"[dim]session:[/dim] {self.session.id}",
            title="[bold red]Prothos — Starting Pipeline[/bold red]",
            border_style="red",
        ))

        try:
            for step in steps:
                self._run_step(step)
        except StopIteration:
            pass
        except RuntimeError as e:
            console.print(f"\n[bold red][!] Pipeline aborted: {e}[/bold red]")
        except KeyboardInterrupt:
            console.print(f"\n[red][!] Pipeline interrupted by user.[/red]")
        finally:
            self.output.finalize()

    def load_recon(self):
        try:
            from recon.tech_fingerprint import run_tech_fingerprint
            self.add_step(
                "tech_fingerprint",
                lambda s: run_tech_fingerprint(s.target, proxy=s.proxy),
                category="recon",
            )
        except ImportError:
            pass

        try:
            from recon.endpoint_discovery import run_endpoint_discovery
            self.add_step(
                "endpoint_discovery",
                lambda s: run_endpoint_discovery(s.target, proxy=s.proxy),
                category="recon",
            )
        except ImportError:
            pass

        try:
            from recon.js_crawler import run_js_scan
            self.add_step(
                "js_crawler",
                lambda s: run_js_scan(s.target, proxy=s.proxy),
                category="recon",
            )
        except ImportError:
            pass

        try:
            from recon.subdomain_bruteforce import run_subdomain_bruteforce
            from urllib.parse import urlparse
            self.add_step(
                "subdomain_bruteforce",
                lambda s: run_subdomain_bruteforce(
                    urlparse(s.target).netloc, proxy=s.proxy
                ),
                category="recon",
            )
        except ImportError:
            pass

        try:
            from recon.passive_subdomains import run_passive_subdomain_scan
            from urllib.parse import urlparse
            self.add_step(
                "passive_subdomains",
                lambda s: run_passive_subdomain_scan(urlparse(s.target).netloc),
                category="recon",
            )
        except ImportError:
            pass

        try:
            from recon.deep_crawler import run_deep_crawler
            self.add_step(
                "deep_crawler",
                lambda s: run_deep_crawler(s.target, proxy=s.proxy),
                category="recon",
                depends_on=["tech_fingerprint"],
            )
        except ImportError:
            pass

    def load_vulnscan(self):
        pass

    def load_all(self):
        self.load_recon()
        self.load_vulnscan()