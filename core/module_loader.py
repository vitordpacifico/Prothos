import importlib
import inspect
from pathlib import Path
from typing import Callable, Optional
from rich.console import Console

console = Console()

class ModuleInfo:
    def __init__(
        self,
        name:        str,
        category:    str,
        fn:          Callable,
        description: str          = "",
        author:      str          = "",
        version:     str          = "1.0.0",
        tags:        list[str]    = None,
        depends_on:  list[str]    = None,
    ):
        self.name        = name
        self.category    = category
        self.fn          = fn
        self.description = description
        self.author      = author
        self.version     = version
        self.tags        = tags or []
        self.depends_on  = depends_on or []

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "category":    self.category,
            "description": self.description,
            "author":      self.author,
            "version":     self.version,
            "tags":        self.tags,
            "depends_on":  self.depends_on,
        }

    def __repr__(self) -> str:
        return f"<Module {self.category}/{self.name} v{self.version}>"

class ModuleLoader:
    KNOWN_MODULES: dict[str, dict[str, str]] = {
        "recon": {
            "tech_fingerprint":      "run_tech_fingerprint",
            "endpoint_discovery":    "run_endpoint_discovery",
            "js_crawler":            "run_js_scan",
            "api_detector":          "run_js_discovery",
            "subdomain_bruteforce":  "run_subdomain_bruteforce",
            "passive_subdomains":    "run_passive_subdomain_scan",
            "deep_crawler":          "run_deep_crawler",
            "microservice_mapper":   "map_services",
            "dns_recon":             "run_dns_recon",
            "wayback_scraper":       "run_wayback_scraper",
            "cloud_enum":            "run_cloud_enum",
            "certificate_enum":      "run_certificate_enum",
            "favicon_hash":          "run_favicon_hash",
            "whois_lookup":          "run_whois_lookup",
            "email_harvester":       "run_email_harvester",
            "github_recon":          "run_github_recon",
            "shodan_query":          "run_shodan_query",
            "social_recon":          "run_social_recon",
        },
        "enumeration": {
            "port_scan":             "run_port_scan",
            "service_detection":     "run_service_detection",
            "vhost_enum":            "run_vhost_enum",
            "parameter_discovery":   "run_parameter_discovery",
            "cors_checker":          "run_cors_checker",
            "api_version_enum":      "run_api_version_enum",
            "graphql_enum":          "run_graphql_enum",
            "websocket_enum":        "run_websocket_enum",
        },
        "vulnscan": {
            "misconfig_scan":        "run_misconfig_scan",
            "subdomain_takeover":    "run_subdomain_takeover",
            "auth_bypass":           "run_auth_bypass",
            "open_redirect_scan":    "run_open_redirect_scan",
            "host_header_inject":    "run_host_header_inject",
            "xss_scan":              "run_xss_scan",
            "sqli_scan":             "run_sqli_scan",
            "lfi_scan":              "run_lfi_scan",
            "ssti_scan":             "run_ssti_scan",
            "ssrf_scan":             "run_ssrf_scan",
            "xxe_scan":              "run_xxe_scan",
            "idor_scan":             "run_idor_scan",
            "oauth_scan":            "run_oauth_scan",
            "graphql_scan":          "run_graphql_scan",
            "websocket_scan":        "run_websocket_scan",
            "prototype_pollution":   "run_prototype_pollution",
            "cache_poisoning":       "run_cache_poisoning",
            "request_smuggling":     "run_request_smuggling",
            "race_condition":        "run_race_condition",
            "business_logic":        "run_business_logic",
            "cve_scanner":           "run_cve_scanner",
        },
        "evasion": {
            "waf_bypass":            "run_waf_bypass",
            "encoder":               "run_encoder",
            "obfuscator":            "run_obfuscator",
            "header_spoof":          "run_header_spoof",
            "chunked_transfer":      "run_chunked_transfer",
        },
        "bruteforce": {
            "login_bruteforce":      "run_login_bruteforce",
            "password_spray":        "run_password_spray",
            "otp_bruteforce":        "run_otp_bruteforce",
            "token_bruteforce":      "run_token_bruteforce",
            "api_key_bruteforce":    "run_api_key_bruteforce",
        },
        "exploit": {
            "exploit_runner":        "run_exploit",
            "xss_prober":            "run_xss_prober",
            "sqli_dumper":           "run_sqli_dumper",
            "lfi_reader":            "run_lfi_reader",
            "ssti_rce":              "run_ssti_rce",
            "ssrf_prober":           "run_ssrf_prober",
            "jwt_attacker":          "run_jwt_attacker",
            "upload_bypass":         "run_upload_bypass",
            "oauth_exploit":         "run_oauth_exploit",
            "graphql_exploit":       "run_graphql_exploit",
            "deserialization":       "run_deserialization",
        },
        "postex": {
            "privilege_check":       "run_privilege_check",
            "credential_finder":     "run_credential_finder",
            "token_extractor":       "run_token_extractor",
            "api_key_validator":     "run_api_key_validator",
            "cloud_metadata":        "run_cloud_metadata",
            "env_reader":            "run_env_reader",
            "session_hijack":        "run_session_hijack",
            "lateral_movement_mapper":"run_lateral_movement_mapper",
            "data_exfil_check":      "run_data_exfil_check",
            "persistence_check":     "run_persistence_check",
        },
    }

    def __init__(self):
        self._registry: dict[str, ModuleInfo] = {}


    def register(self, module: ModuleInfo):
        self._registry[module.name] = module

    def register_fn(
        self,
        name:        str,
        category:    str,
        fn:          Callable,
        **kwargs,
    ):
        self.register(ModuleInfo(
            name=name,
            category=category,
            fn=fn,
            **kwargs,
        ))


    def autodiscover(self, verbose: bool = False):
        for category, modules in self.KNOWN_MODULES.items():
            for mod_name, fn_name in modules.items():
                self._try_load(category, mod_name, fn_name, verbose)

    def _try_load(
        self,
        category: str,
        mod_name: str,
        fn_name:  str,
        verbose:  bool = False,
    ):
        module_path = f"{category}.{mod_name}"
        try:
            mod = importlib.import_module(module_path)
            fn  = getattr(mod, fn_name, None)

            if fn is None:
                if verbose:
                    console.print(
                        f"[yellow][!] {module_path} loaded but "
                        f"'{fn_name}' not found[/yellow]"
                    )
                return

            description = (inspect.getdoc(fn) or "").split("\n")[0]

            self.register(ModuleInfo(
                name=mod_name,
                category=category,
                fn=fn,
                description=description,
            ))

            if verbose:
                console.print(f"[dim]    [+] Loaded {category}/{mod_name}[/dim]")

        except ImportError:
            if verbose:
                console.print(f"[dim]    [-] Not yet implemented: {module_path}[/dim]")
        except Exception as e:
            if verbose:
                console.print(f"[red]    [!] Error loading {module_path}: {e}[/red]")

    def load_plugins(self, plugins_dir: str | Path = "plugins", verbose: bool = False):
        plugins_path = Path(plugins_dir)
        if not plugins_path.exists():
            return

        for plugin_file in plugins_path.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue
            self._try_load_plugin(plugin_file, verbose)

    def _try_load_plugin(self, path: Path, verbose: bool = False):
        try:
            spec   = importlib.util.spec_from_file_location(path.stem, path)
            mod    = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            meta = getattr(mod, "PROTHOS_MODULE", None)
            if not meta:
                if verbose:
                    console.print(f"[yellow][!] {path.name} has no PROTHOS_MODULE[/yellow]")
                return

            fn_name = meta.get("fn", "run")
            fn      = getattr(mod, fn_name, None)
            if not fn:
                console.print(f"[red][!] Plugin {path.name}: function '{fn_name}' not found[/red]")
                return

            self.register(ModuleInfo(
                name=meta.get("name", path.stem),
                category=meta.get("category", "recon"),
                fn=fn,
                description=meta.get("description", ""),
                author=meta.get("author", ""),
                version=meta.get("version", "1.0.0"),
                tags=meta.get("tags", []),
                depends_on=meta.get("depends_on", []),
            ))

            if verbose:
                console.print(f"[dim]    [+] Plugin loaded: {path.name}[/dim]")

        except Exception as e:
            console.print(f"[red][!] Failed to load plugin {path.name}: {e}[/red]")

    def get(self, name: str) -> Optional[ModuleInfo]:
        return self._registry.get(name)

    def get_by_category(self, category: str) -> list[ModuleInfo]:
        return [m for m in self._registry.values() if m.category == category]

    def get_by_tag(self, tag: str) -> list[ModuleInfo]:
        return [m for m in self._registry.values() if tag in m.tags]

    def all(self) -> list[ModuleInfo]:
        return list(self._registry.values())

    def categories(self) -> list[str]:
        return sorted(set(m.category for m in self._registry.values()))

    def is_loaded(self, name: str) -> bool:
        return name in self._registry

    def list_modules(self):
        from rich.table import Table

        table = Table(
            show_header=True,
            header_style="bold red",
            border_style="dim",
        )
        table.add_column("Category", style="red",   width=14)
        table.add_column("Module",   style="white",  width=24)
        table.add_column("Description", style="dim")

        for cat in self.KNOWN_MODULES.keys():
            mods = self.get_by_category(cat)
            for m in mods:
                table.add_row(cat, m.name, m.description or "-")

        console.print(table)

    def summary(self) -> dict:
        return {
            "total":      len(self._registry),
            "categories": {
                cat: len(self.get_by_category(cat))
                for cat in self.categories()
            },
        }

_loader: Optional[ModuleLoader] = None

def get_loader() -> ModuleLoader:
    global _loader
    if _loader is None:
        _loader = ModuleLoader()
    return _loader

def autodiscover(verbose: bool = False) -> ModuleLoader:
    loader = get_loader()
    loader.autodiscover(verbose=verbose)
    loader.load_plugins(verbose=verbose)
    return loader