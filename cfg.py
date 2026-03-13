import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

BASE_DIR      = Path(__file__).resolve().parent
WORDLIST_DIR  = BASE_DIR / "wordlists"
OUTPUT_DIR    = BASE_DIR / "output"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
@dataclass
class ProthosConfig:

    target: str = ""
    scope: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)

    concurrency: int = 50
    timeout: int     = 10
    retries: int     = 2
    delay: float     = 0.0

    wordlist_endpoints: Path = WORDLIST_DIR / "endpoints.txt"
    wordlist_params:    Path = WORDLIST_DIR / "params.txt"
    wordlist_subdomains:Path = WORDLIST_DIR / "subdomains.txt"

    user_agent: str = "Mozilla/5.0 (compatible; Prothos/1.0)"
    follow_redirects: bool  = True
    verify_ssl: bool        = False
    headers: dict           = field(default_factory=dict)
    cookies: dict           = field(default_factory=dict)
    proxy: Optional[str]    = None

    output_dir:  Path = OUTPUT_DIR
    output_json: Path = field(init=False)
    output_html: Path = field(init=False)
    verbose: bool     = False
    silent: bool      = False

    def __post_init__(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_json = self.output_dir / f"report_{ts}.json"
        self.output_html = self.output_dir / f"report_{ts}.html"

    def validate(self):
        """Valida campos críticos antes de iniciar qualquer módulo."""
        if not self.target:
            raise ValueError("[config] 'target' is required.")
        if self.concurrency < 1 or self.concurrency > 500:
            raise ValueError("[config] 'concurrency' must be between 1 and 500.")
        if self.timeout < 1:
            raise ValueError("[config] 'timeout' must be >= 1 second.")
        for wl in (self.wordlist_endpoints, self.wordlist_params, self.wordlist_subdomains):
            if not wl.exists():
                print(f"[warn] Wordlist not found: {wl}")

config = ProthosConfig()

def load_from_env():
    """Sobrescreve config com variáveis de ambiente, se definidas."""
    if t := os.getenv("PROTHOS_TARGET"):
        config.target = t
    if c := os.getenv("PROTHOS_CONCURRENCY"):
        config.concurrency = int(c)
    if t := os.getenv("PROTHOS_TIMEOUT"):
        config.timeout = int(t)
    if p := os.getenv("PROTHOS_PROXY"):
        config.proxy = p
    if os.getenv("PROTHOS_VERBOSE", "").lower() in ("1", "true"):
        config.verbose = True
    if os.getenv("PROTHOS_SILENT", "").lower() in ("1", "true"):
        config.silent = True