```
██████╗ ██████╗  ██████╗ ████████╗██╗  ██╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██║  ██║██╔═══██╗██╔════╝
██████╔╝██████╔╝██║   ██║   ██║   ███████║██║   ██║███████╗
██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══██║██║   ██║╚════██║
██║     ██║  ██║╚██████╔╝   ██║   ██║  ██║╚██████╔╝███████║
╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

> **recon. enumerate. assess. report.**

![Python](https://img.shields.io/badge/python-3.11+-red?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-red?style=flat-square)
![Status](https://img.shields.io/badge/status-active-red?style=flat-square)

Prothos is a modular offensive-security **assessment** framework for authorized engagements. It chains passive OSINT, active enumeration, fingerprinting, crawling, vulnerability detection, out-of-band confirmation and structured reporting into a single CLI pipeline — and integrates the dedicated tools your team already runs (Burp, Nuclei, sqlmap, hydra, Metasploit, DefectDojo).

---

## ▸ Scope & philosophy

Prothos covers the engagement lifecycle: **pre-engagement → recon → threat modeling → assessment → exploitation → post-engagement → reporting**.

- **Recon, detection, confirmation, threat modeling and reporting are built in.**
- **Native exploitation** (sqli/ssti/cmdi/lfi/ssrf) is built in, behind hard safety rails.
- **C2, persistence and lateral movement remain delegated** to vetted, auditable external tools (Metasploit, Sliver, etc.) through the runner integrations. Prothos orchestrates them and ingests their results; it does not reimplement post-breach operation or command-and-control.

### Safety rails (always enforced for active actions)

1. **Scope guard** — every request is checked against the engagement scope; out-of-scope traffic is blocked. (`core/scope.py`)
2. **Rules of Engagement** — exploitation/post-ex require explicit consent (`allow_exploit` / `allow_postex`) or **lab mode**. (`core/roe.py`)
3. **Audit trail** — every payload, exploit and planted artifact is logged append-only to `output/audit-<session>.jsonl`. Always on. (`core/audit.py`)

`Lab mode` (CLI option `L`) disables the scope guard for owned/CTF targets only; the audit trail stays on.

> Use only against systems you are explicitly authorized to test. See Disclaimer.

---

## ▸ Engagement phases

| Phase | Coverage | Modules |
|-------|----------|---------|
| 1. Pre-engagement | ✅ rails | `core/scope`, `core/roe`, `core/audit` |
| 2. Recon | ✅ | `recon/` (18) |
| 3. Threat modeling | ✅ | `core/threat_model` — prioritized attack plan |
| 4. Assessment | ✅ | `enumeration/` (8), `vulnscan/` (21) |
| 5. Exploitation | ✅ native + delegated | `exploitation/` (5) + integration runners |
| 6. Post-exploitation | 🟡 audit-oriented | `postex/` (privesc enum, loot, creds, tokens) |
| 7. Reporting | ✅ | `output/` (json/html/md/pdf/sarif) |
| 8. Post-engagement | ✅ | `core/artifacts` (cleanup), `core/retest` (diff) |

### exploitation (5) — gated

```
sqli_exploit   ssti_exploit   cmdi_exploit   lfi_exploit   ssrf_exploit
```

Each acts on a **confirmed** finding and refuses to run without scope + consent
(or lab mode). Example:

```python
from exploitation.sqli_exploit import run_sqli_exploit
report = run_sqli_exploit("https://target/item?id=1", param="id",
                          allow_exploit=True, save_json="output/sqli_exploit.json")
```

### Threat model & post-engagement

```python
from core.threat_model import run_threat_model   # prioritized attack plan
from core.artifacts   import run_cleanup_report  # what to revert
from core.retest      import run_retest          # diff vs. a previous session
```

---

## ▸ Module categories

| Category | Count | What it covers |
|----------|-------|----------------|
| `recon` | 18 | fingerprint, endpoints, JS, subdomains (brute + passive), crawl, DNS, wayback, certs, favicon, whois, cloud, email, github, shodan, social |
| `enumeration` | 8 | port scan, service detection, vhosts, parameter discovery, CORS, API versions, GraphQL, WebSocket |
| `vulnscan` | 21 | detection scanners (see below) |
| `exploitation` | 5 | native exploit modules — sqli, ssti, cmdi, lfi, ssrf (gated, see below) |
| `evasion` | 1 | payload encoder (url/html/unicode/hex/base64/mixed) |
| `postex` | 6 | privilege check/enum, credential finder, loot collector, token extractor, session security (audit-oriented) |
| `fuzzing` | 2 | parameter fuzzer, HTTP method enumeration |

### vulnscan (21)

```
subdomain_takeover   auth_bypass          open_redirect_scan   host_header_inject
sqli_scan            xss_scan             lfi_scan             ssrf_scan
ssti_scan            idor_scan            xxe_scan             oauth_scan
request_smuggling    race_condition       cve_scanner          misconfig_scan
graphql_scan         websocket_scan       prototype_pollution  cache_poisoning
business_logic
```

All vulnscan modules are **detection/confirmation** oriented: they identify and evidence the issue. Severity: `critical / high / medium / low / info`.

---

## ▸ Out-of-band confirmation (`c2/`)

Listeners to confirm blind SSRF / XXE / blind SQLi:

| Module | Entry point |
|--------|-------------|
| `c2/http_log.py` | `run_http_log` — async HTTP callback logger |
| `c2/dns_log.py` | `run_dns_log` — UDP DNS callback logger |
| `c2/interactsh_client.py` | `run_interactsh_client` — interactsh OOB integration (RSA/AES) |

---

## ▸ Integrations (`integrations/`)

| Module | Entry point | Notes |
|--------|-------------|-------|
| `burp_export.py` | `run_burp_export` | findings/endpoints → Burp sitemap XML |
| `nuclei_runner.py` | `run_nuclei_runner` | runs Nuclei, imports findings |
| `sqlmap_runner.py` | `run_sqlmap_runner` | orchestrates sqlmap on confirmed params |
| `hydra_runner.py` | `run_hydra_runner` | orchestrates hydra (credential testing) |
| `metasploit_bridge.py` | `run_metasploit_bridge` | msfrpc client (list/info/execute) |
| `defectdojo_push.py` | `run_defectdojo_push` | pushes findings to DefectDojo |

The runners require the corresponding tool installed and authorized; the exploitation logic lives in those audited tools, not in Prothos.

---

## ▸ Reporting (`output/`)

| Format | Entry point |
|--------|-------------|
| JSON (+gzip) | `output.json_exporter.export_json` |
| HTML | `output.html_exporter.export_html` |
| Markdown (CVSS + TOC) | `output.markdown_report.run_markdown_report` |
| PDF (cover + exec summary) | `output.pdf_report.run_pdf_report` |
| SARIF 2.1.0 | `output.sarif_export.run_sarif_export` |

---

## ▸ Installation

```bash
git clone https://github.com/vitordpacifico/Prothos
cd Prothos
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
```

**requirements.txt**
```
httpx[http2]   aiohttp        beautifulsoup4   lxml
rich           requests       dnspython        mmh3
reportlab      cryptography   msgpack
```

Optional external tools (for the runner integrations): `nuclei`, `sqlmap`, `hydra`, a running `msfrpcd`.

> On Windows, if the ASCII banner errors with a charmap codec, set `PYTHONIOENCODING=utf-8`.

---

## ▸ Usage

```bash
python main.py
```

The CLI auto-discovers every implemented module by category and presents:

```
  [1] Scan Modules        recon / enum / vulnscan / exploitation / postex
  [2] OOB / Confirmation  http / dns / interactsh listeners
  [3] Tools               encoder
  [4] Output              json / html / markdown / pdf / sarif / burp
  [5] Session             show / save / load
  [6] Threat Model        prioritized attack plan from findings
  [7] Post-Engagement     cleanup report / retest diff
  [L] Lab mode            scope guard off (owned/CTF only)
  [0] Exit
```

Submenus: Social Recon (domain/person), Subdomain (brute/passive/engine), Port Scan (common/web/db/full), Cloud Enum (auto/custom), Email Harvester (harvest/HIBP/spray-list). "Run All" executes the recon → enum → vulnscan pipeline and accumulates findings into a session for export.

Modules are also callable directly:

```python
from vulnscan.sqli_scan import run_sqli_scan
report = run_sqli_scan("https://target/path?id=1", proxy="http://127.0.0.1:8080",
                       save_json="output/sqli.json")
```

---

## ▸ Project structure

```
prothos/
├── main.py                     # entry point
├── cli.py                      # interactive CLI (dynamic module discovery)
├── core/                       # session, engine, requester, analyzer, loader,
│                               #   scope, roe, audit, threat_model, artifacts, retest
├── recon/                      # 18 recon modules
├── enumeration/                # 8 enumeration modules
├── vulnscan/                   # 21 detection scanners
├── exploitation/               # 5 native exploit modules (gated)
├── evasion/                    # encoder
├── postex/                     # privesc_enum, loot_collector, credential_finder,
│                               #   token_extractor, privilege_check (audit)
├── c2/                         # http_log, dns_log, interactsh_client (OOB)
├── fuzzing/                    # param_fuzzer, method_enum
├── integrations/               # burp, nuclei, sqlmap, hydra, metasploit, defectdojo
├── output/                     # json, html, markdown, pdf, sarif exporters
└── wordlist/                   # endpoints, microservices, ...
```

---

## ▸ Conventions

- Async-first (`asyncio` + `httpx`), `asyncio.Semaphore` for concurrency.
- Every module exposes `run_<module>(target, ..., proxy=None, save_json=None)` returning a dataclass `Report` with `to_dict()`.
- Findings printed in real time; `rich` Panel/Table summaries.
- Severity levels: `critical / high / medium / low / info`.

---

## ▸ Disclaimer

> This tool is intended for authorized security testing and educational purposes only.
> Always obtain proper written permission before testing any system, and stay within the
> agreed Rules of Engagement. The authors are not responsible for misuse or damage.

---

<p align="center">
  <sub>built for the <strong>red</strong> side — used responsibly</sub>
</p>
