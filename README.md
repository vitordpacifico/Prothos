```
██████╗ ██████╗  ██████╗ ████████╗██╗  ██╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██║  ██║██╔═══██╗██╔════╝
██████╔╝██████╔╝██║   ██║   ██║   ███████║██║   ██║███████╗
██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══██║██║   ██║╚════██║
██║     ██║  ██║╚██████╔╝   ██║   ██║  ██║╚██████╔╝███████║
╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

> **recon. enumerate. dominate.**

![Python](https://img.shields.io/badge/python-3.11+-red?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-red?style=flat-square)
![Status](https://img.shields.io/badge/status-active-red?style=flat-square)

Prothos is a modular red team recon framework built for offensive security professionals. It chains passive OSINT, active enumeration, fingerprinting, crawling, and fuzzing into a single CLI pipeline — with structured JSON/HTML reporting.

---

## ▸ Features

| Module | Description |
|--------|-------------|
| `Subdomain Bruteforce` | Async DNS bruteforce with wildcard detection, takeover check, HTTP probe |
| `Passive Subdomain Scan` | 7 OSINT sources: crt.sh, AlienVault, HackerTarget, urlscan, RapidDNS, Wayback, ThreatCrowd |
| `Tech Fingerprint` | 90+ signatures — WAF, CDN, Cloud, Framework, CMS, Backend, SSL, Security Headers |
| `Deep Crawler` | BFS async crawler — forms, params, HTML comments, emails, secrets |
| `JS Scanner` | Extracts endpoints, API paths, webpack chunks, source maps, 14 secret patterns |
| `Endpoint Discovery` | Soft-404 calibration, critical path detection, body analysis |
| `Microservice Mapper` | Async path probing with response intelligence |
| `Method Enumeration` | 16 HTTP methods, WebDAV, 403 bypass, CORS wildcard detection |
| `Parameter Fuzzer` | SQLi, XSS, SSTI, SSRF, LFI, RCE, XXE, CMDi — time-based detection |

---

## ▸ Installation

```bash
git clone https://github.com/your/prothos
cd prothos
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**requirements.txt**
```
aiohttp
beautifulsoup4
lxml
rich
requests
httpx
dnspython
```

---

## ▸ Usage

```bash
python main.py
```

```
  ┌─────────────────────────────────────────┐
  │              PROTHOS RECON              │
  └─────────────────────────────────────────┘

  [ DISCOVERY ]
  [1] Endpoint Discovery
  [2] JavaScript Recon
  [3] API Detection
  [4] Parameter Fuzzing
  [5] Microservice Mapping

  [ ENUMERATION ]
  [6] Subdomain Bruteforce
  [7] Passive Subdomain Scan
  [8] Deep Crawler

  [ FINGERPRINT ]
  [9] Tech Fingerprint

  [ FULL SCAN ]
  [A] Run All Modules on Target

  [0] Exit

prothos>
```

---

## ▸ Output

Every module returns a structured dataclass report exportable as **JSON** or **HTML**.

```python
from output.json_exporter import export_json_multi
from output.html_exporter import export_html_multi

export_json_multi({
    "target":      "https://target.com",
    "fingerprint": fp_report,
    "subdomains":  sub_report,
    "endpoints":   ep_report,
    "fuzzing":     fuzz_report,
    "js_scan":     js_report,
}, "output/report.json")

export_html_multi({...}, "output/report.html")
```

**HTML report preview:**
- Dark themed, standalone (no external deps)
- Collapsible sections per module
- Live filter on every table
- Severity badges (critical / high / medium / low)
- Stats bar with finding counts
- Raw JSON viewer

---

## ▸ Project Structure

```
prothos/
│
├── main.py                     # entry point
├── cli.py                      # interactive CLI menu
├── cfg.py                      # global config (ProthosConfig)
├── requirements.txt
│
├── recon/
│   ├── subdomain_bruteforce.py # async DNS bruteforce
│   ├── passive_subdomains.py   # OSINT aggregator (7 sources)
│   ├── tech_fingerprint.py     # 90+ tech signatures
│   ├── deep_crawler.py         # BFS async crawler
│   ├── js_crawler.py           # JS analysis + secret scan
│   ├── endpoint_discovery.py   # wordlist-based discovery
│   └── microservice_mapper.py  # path probing
│
├── fuzzing/
│   ├── param_fuzzer.py         # parameter fuzzing engine
│   └── method_enum.py          # HTTP method enumeration
│
├── engines/
│   └── subbrute_engine.py      # bruteforce + passive pipeline
│
├── core/
│   ├── requester.py            # async HTTP client
│   └── analyzer.py             # response analysis (44 rules)
│
├── output/
│   ├── json_exporter.py        # JSON + gzip export
│   └── html_exporter.py        # standalone HTML report
│
└── wordlists/
    ├── subdomains.txt          # 433 entries, categorized
    ├── endpoints.txt           # 544 entries, categorized
    └── microservices.txt       # service paths
```

---

## ▸ Wordlists

| File | Entries | Categories |
|------|---------|------------|
| `subdomains.txt` | 433 | Admin, Auth, Billing, API, Infra, Monitoring, CDN, Staging, Legacy... |
| `endpoints.txt` | 544 | Auth, Admin, API versioned, Debug, Actuator, Config, Docs, Legacy... |
| `microservices.txt` | custom | Service paths and internal routes |

---

## ▸ Proxy Support

All modules support routing through **Burp Suite** or **ZAP**:

```python
run_tech_fingerprint(target, proxy="http://127.0.0.1:8080")
run_subdomain_bruteforce(domain, proxy="http://127.0.0.1:8080")
fuzz_params(url, params, proxy="http://127.0.0.1:8080")
```

---

## ▸ Disclaimer

> This tool is intended for authorized security testing and educational purposes only.
> Always obtain proper written permission before testing any system.
> The author is not responsible for any misuse or damage caused by this tool.

---

<p align="center">
  <sub>built for the <strong>red</strong> side</sub>
</p>