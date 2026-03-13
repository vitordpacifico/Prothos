import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from output.json_exporter import _serialize

console = Console()


def _build_html(data: dict) -> str:

    target    = data.get("target", "Unknown Target")
    now       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    data_json = json.dumps(data, indent=2, ensure_ascii=False, default=str)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Prothos Report — {target}</title>
  <style>
    :root {{
      --bg:       #0d0d0d;
      --surface:  #141414;
      --border:   #2a2a2a;
      --red:      #e63946;
      --orange:   #f4845f;
      --yellow:   #ffd166;
      --green:    #06d6a0;
      --cyan:     #48cae4;
      --white:    #f0f0f0;
      --dim:      #666;
      --critical: #e63946;
      --high:     #f4845f;
      --medium:   #ffd166;
      --low:      #666;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--white);
      font-family: 'Courier New', monospace;
      font-size: 13px;
      line-height: 1.6;
    }}
    .header {{
      background: var(--surface);
      border-bottom: 1px solid var(--red);
      padding: 24px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .logo {{
      color: var(--red);
      font-size: 22px;
      font-weight: bold;
      letter-spacing: 6px;
      text-transform: uppercase;
    }}
    .meta {{ color: var(--dim); font-size: 11px; text-align: right; }}
    .meta span {{ color: var(--white); }}
    .container {{ max-width: 1400px; margin: 0 auto; padding: 24px 32px; }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin-bottom: 32px;
    }}
    .stat-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 16px;
      text-align: center;
    }}
    .stat-card .num {{ font-size: 28px; font-weight: bold; display: block; }}
    .stat-card .label {{
      color: var(--dim);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1px;
    }}
    .stat-card.critical .num {{ color: var(--critical); }}
    .stat-card.high     .num {{ color: var(--high); }}
    .stat-card.medium   .num {{ color: var(--medium); }}
    .stat-card.green    .num {{ color: var(--green); }}
    .stat-card.cyan     .num {{ color: var(--cyan); }}
    .section {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 4px;
      margin-bottom: 20px;
      overflow: hidden;
    }}
    .section-header {{
      background: #1a1a1a;
      border-bottom: 1px solid var(--border);
      padding: 12px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      cursor: pointer;
      user-select: none;
    }}
    .section-header:hover {{ background: #222; }}
    .section-title {{
      color: var(--red);
      font-weight: bold;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 2px;
    }}
    .section-count {{
      background: var(--border);
      color: var(--white);
      border-radius: 12px;
      padding: 2px 10px;
      font-size: 11px;
    }}
    .section-body {{ padding: 16px 20px; }}
    .section-body.hidden {{ display: none; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
    th {{
      color: var(--dim);
      text-transform: uppercase;
      letter-spacing: 1px;
      font-size: 10px;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
    }}
    td {{
      padding: 8px 12px;
      border-bottom: 1px solid #1e1e1e;
      vertical-align: top;
      word-break: break-all;
    }}
    tr:hover td {{ background: #1a1a1a; }}
    tr:last-child td {{ border-bottom: none; }}
    .badge {{
      display: inline-block;
      padding: 1px 8px;
      border-radius: 3px;
      font-size: 10px;
      font-weight: bold;
      text-transform: uppercase;
      letter-spacing: 1px;
    }}
    .badge.critical {{ background: rgba(230,57,70,0.2);  color: var(--critical); border: 1px solid var(--critical); }}
    .badge.high     {{ background: rgba(244,132,95,0.2); color: var(--high);     border: 1px solid var(--high); }}
    .badge.medium   {{ background: rgba(255,209,102,0.2);color: var(--medium);   border: 1px solid var(--medium); }}
    .badge.low      {{ background: rgba(102,102,102,0.2);color: var(--dim);      border: 1px solid var(--dim); }}
    .status {{ font-weight: bold; }}
    .s2xx {{ color: var(--green); }}
    .s3xx {{ color: var(--yellow); }}
    .s4xx {{ color: var(--cyan); }}
    .s5xx {{ color: var(--red); }}
    .mono     {{ font-family: 'Courier New', monospace; color: var(--cyan); }}
    .dim      {{ color: var(--dim); }}
    .red      {{ color: var(--red); }}
    .green    {{ color: var(--green); }}
    .url      {{ color: var(--cyan); font-size: 11px; }}
    .evidence {{ color: var(--yellow); font-size: 11px; font-style: italic; }}
    .tag {{
      display: inline-block;
      background: var(--border);
      color: var(--white);
      border-radius: 3px;
      padding: 1px 6px;
      font-size: 10px;
      margin: 1px;
    }}
    .search-bar {{
      width: 100%;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 4px;
      color: var(--white);
      padding: 8px 12px;
      font-family: monospace;
      font-size: 12px;
      margin-bottom: 12px;
      outline: none;
    }}
    .search-bar:focus {{ border-color: var(--red); }}
    .json-viewer {{
      background: #0a0a0a;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 16px;
      overflow: auto;
      max-height: 500px;
      font-size: 11px;
      color: var(--dim);
      white-space: pre;
    }}
    .footer {{
      text-align: center;
      padding: 32px;
      color: var(--dim);
      font-size: 11px;
      border-top: 1px solid var(--border);
      margin-top: 32px;
    }}
  </style>
</head>
<body>

<div class="header">
  <div>
    <div class="logo">Prothos</div>
    <div class="dim" style="margin-top:4px; font-size:11px;">Red Team Recon Framework</div>
  </div>
  <div class="meta">
    <div>Target: <span>{target}</span></div>
    <div>Generated: <span>{now}</span></div>
    <div>Tool: <span>Prothos v1.0.0</span></div>
  </div>
</div>

<div class="container" id="app">
  <div class="stats" id="stats-bar"></div>
  <div id="sections"></div>
  <div class="section">
    <div class="section-header" onclick="toggleSection(this)">
      <span class="section-title">Raw JSON</span>
      <span class="section-count">view</span>
    </div>
    <div class="section-body hidden">
      <div class="json-viewer" id="raw-json"></div>
    </div>
  </div>
</div>

<div class="footer">
  Generated by <span style="color:var(--red)">Prothos</span> — {now}
</div>

<script>
const RAW = {data_json};

function statusClass(s) {{
  if (s >= 500) return 's5xx';
  if (s >= 400) return 's4xx';
  if (s >= 300) return 's3xx';
  if (s >= 200) return 's2xx';
  return 'dim';
}}

function badge(sev) {{
  if (!sev) return '';
  return `<span class="badge ${{sev}}">${{sev}}</span>`;
}}

function tag(t) {{
  return `<span class="tag">${{t}}</span>`;
}}

function toggleSection(el) {{
  el.nextElementSibling.classList.toggle('hidden');
}}

function filterTable(input, tableId) {{
  const q = input.value.toLowerCase();
  document.querySelectorAll(`#${{tableId}} tbody tr`).forEach(tr => {{
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}

function buildStats() {{
  const bar      = document.getElementById('stats-bar');
  const cards    = [];
  const subs     = (RAW.subdomains?.found || RAW.passive?.found || []).length;
  const eps      = (RAW.endpoints?.found || []).length;
  const findings = (RAW.fuzzing?.findings || []);
  const critical = findings.filter(f => f.severity === 'critical').length;
  const high     = findings.filter(f => f.severity === 'high').length;
  const secrets  = (RAW.js_scan?.secrets || []).length;
  const js       = (RAW.js_scan?.js_files || []).length;
  if (subs)     cards.push({{ num: subs,     label: 'Subdomains', cls: 'cyan' }});
  if (eps)      cards.push({{ num: eps,      label: 'Endpoints',  cls: 'green' }});
  if (critical) cards.push({{ num: critical, label: 'Critical',   cls: 'critical' }});
  if (high)     cards.push({{ num: high,     label: 'High',       cls: 'high' }});
  if (secrets)  cards.push({{ num: secrets,  label: 'Secrets',    cls: 'critical' }});
  if (js)       cards.push({{ num: js,       label: 'JS Files',   cls: 'cyan' }});
  bar.innerHTML = cards.map(c => `
    <div class="stat-card ${{c.cls}}">
      <span class="num">${{c.num}}</span>
      <span class="label">${{c.label}}</span>
    </div>`).join('');
}}

function section(title, count, bodyHtml) {{
  return `
    <div class="section">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-title">${{title}}</span>
        <span class="section-count">${{count}}</span>
      </div>
      <div class="section-body">${{bodyHtml}}</div>
    </div>`;
}}

function buildSubdomains() {{
  const found = RAW.subdomains?.found || RAW.passive?.found || RAW.bruteforce?.found || [];
  if (!found.length) return '';
  const rows = found.map(r => `
    <tr>
      <td class="mono">${{r.subdomain}}</td>
      <td class="dim">${{(r.ip||[]).join(', ') || r.cname || '-'}}</td>
      <td><span class="status ${{statusClass(r.http_status||0)}}">${{r.http_status||'-'}}</span></td>
      <td><span class="status ${{statusClass(r.https_status||0)}}">${{r.https_status||'-'}}</span></td>
      <td class="dim">${{r.cdn||'-'}}</td>
      <td>${{r.takeover_risk ? `<span class="badge critical">⚠ ${{r.takeover_hint}}</span>` : '-'}}</td>
      <td class="dim">${{r.http_title||'-'}}</td>
    </tr>`).join('');
  return section('Subdomains', found.length, `
    <input class="search-bar" placeholder="Filter subdomains..." oninput="filterTable(this,'tbl-subs')">
    <table id="tbl-subs">
      <thead><tr><th>Subdomain</th><th>IP / CNAME</th><th>HTTP</th><th>HTTPS</th><th>CDN</th><th>Takeover</th><th>Title</th></tr></thead>
      <tbody>${{rows}}</tbody>
    </table>`);
}}

function buildEndpoints() {{
  const found = RAW.endpoints?.found || RAW.microservices?.found || [];
  if (!found.length) return '';
  const rows = found.map(r => `
    <tr>
      <td><span class="status ${{statusClass(r.status)}}">${{r.status}}</span></td>
      <td class="mono">${{r.path}}</td>
      <td class="dim">${{r.title||'-'}}</td>
      <td class="dim">${{r.content_len ? r.content_len+'b' : '-'}}</td>
      <td class="dim">${{r.response_time||'-'}}s</td>
      <td>${{(r.notes||[]).map(n => `<span class="tag">${{n}}</span>`).join(' ')}}</td>
    </tr>`).join('');
  return section('Endpoints', found.length, `
    <input class="search-bar" placeholder="Filter endpoints..." oninput="filterTable(this,'tbl-eps')">
    <table id="tbl-eps">
      <thead><tr><th>Status</th><th>Path</th><th>Title</th><th>Size</th><th>Time</th><th>Notes</th></tr></thead>
      <tbody>${{rows}}</tbody>
    </table>`);
}}

function buildFindings() {{
  const findings = RAW.fuzzing?.findings || [];
  if (!findings.length) return '';
  const rows = findings.map(f => `
    <tr>
      <td>${{badge(f.severity)}}</td>
      <td class="mono">${{f.param}}</td>
      <td class="dim">${{f.category}}</td>
      <td class="red">${{f.issue}}</td>
      <td><span class="status ${{statusClass(f.status)}}">${{f.status||'-'}}</span></td>
      <td class="dim">${{f.response_time}}s</td>
      <td class="evidence">${{(f.payload||'').substring(0,50)}}</td>
      <td class="dim" style="font-size:10px">${{(f.evidence||'').substring(0,80)}}</td>
    </tr>`).join('');
  return section('Fuzzing Findings', findings.length, `
    <input class="search-bar" placeholder="Filter findings..." oninput="filterTable(this,'tbl-fuzz')">
    <table id="tbl-fuzz">
      <thead><tr><th>Severity</th><th>Param</th><th>Category</th><th>Issue</th><th>Status</th><th>Time</th><th>Payload</th><th>Evidence</th></tr></thead>
      <tbody>${{rows}}</tbody>
    </table>`);
}}

function buildFingerprint() {{
  const fp = RAW.fingerprint;
  if (!fp) return '';
  const rows = [
    ['Server',    fp.server],
    ['Powered By',fp.powered_by],
    ['WAF',       (fp.waf||[]).join(', ')],
    ['CDN',       (fp.cdn||[]).join(', ')],
    ['Cloud',     (fp.cloud||[]).join(', ')],
    ['Backend',   (fp.backend||[]).join(', ')],
    ['Framework', (fp.frameworks||[]).join(', ')],
    ['CMS',       (fp.cms||[]).join(', ')],
    ['Language',  (fp.languages||[]).join(', ')],
    ['IP',        fp.ip],
    ['Status',    fp.status_code],
  ].filter(([,v]) => v).map(([k,v]) => `
    <tr>
      <td style="color:var(--dim);width:160px">${{k}}</td>
      <td class="mono">${{v}}</td>
    </tr>`).join('');
  const secRows = Object.entries(fp.security_headers||{{}}).map(([h,v]) => `
    <tr>
      <td class="dim" style="width:300px">${{h}}</td>
      <td class="${{v==='MISSING'?'red':'green'}}">${{v==='MISSING'?'✗ MISSING':'✓'}}</td>
      <td class="dim" style="font-size:11px">${{v!=='MISSING'?v:''}}</td>
    </tr>`).join('');
  return section('Tech Fingerprint', fp.status_code||'', `
    <table style="margin-bottom:20px"><tbody>${{rows}}</tbody></table>
    <div style="color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Security Headers</div>
    <table><tbody>${{secRows}}</tbody></table>`);
}}

function buildSecrets() {{
  const secrets = RAW.js_scan?.secrets || [];
  if (!secrets.length) return '';
  const rows = secrets.map(s => `
    <tr>
      <td><span class="badge critical">${{s.kind}}</span></td>
      <td class="evidence">${{s.value}}</td>
      <td class="dim">line ${{s.line}}</td>
      <td class="dim" style="font-size:10px">${{s.js_url}}</td>
    </tr>`).join('');
  return section('⚠ Secrets Found', secrets.length, `
    <table>
      <thead><tr><th>Type</th><th>Value</th><th>Line</th><th>File</th></tr></thead>
      <tbody>${{rows}}</tbody>
    </table>`);
}}

function buildJSFiles() {{
  const files = RAW.js_scan?.js_files || RAW.js_discovery?.js_files || [];
  if (!files.length) return '';
  const rows = files.map(f => `
    <tr>
      <td class="dim">${{f.kind}}</td>
      <td class="url">${{f.url}}</td>
      <td>${{(f.categories||[]).map(tag).join('')}}</td>
      <td>${{f.source_map ? '<span class="badge critical">⚠ .map</span>' : '-'}}</td>
      <td class="dim">${{f.size ? Math.round(f.size/1024)+'KB' : '-'}}</td>
    </tr>`).join('');
  return section('JS Files', files.length, `
    <input class="search-bar" placeholder="Filter JS files..." oninput="filterTable(this,'tbl-js')">
    <table id="tbl-js">
      <thead><tr><th>Kind</th><th>URL</th><th>Categories</th><th>Source Map</th><th>Size</th></tr></thead>
      <tbody>${{rows}}</tbody>
    </table>`);
}}

function buildMethods() {{
  const found = RAW.methods?.allowed || [];
  if (!found.length) return '';
  const rows = found.map(m => `
    <tr>
      <td class="mono">${{m.method}}</td>
      <td><span class="status ${{statusClass(m.status)}}">${{m.status}}</span></td>
      <td class="dim">${{m.response_time}}s</td>
      <td>${{m.dangerous ? '<span class="badge critical">DANGEROUS</span>' : '-'}}</td>
      <td>${{(m.notes||[]).map(tag).join('')}}</td>
    </tr>`).join('');
  return section('HTTP Methods', found.length, `
    <table>
      <thead><tr><th>Method</th><th>Status</th><th>Time</th><th>Risk</th><th>Notes</th></tr></thead>
      <tbody>${{rows}}</tbody>
    </table>`);
}}

function init() {{
  buildStats();
  document.getElementById('sections').innerHTML = [
    buildFindings(),
    buildSecrets(),
    buildSubdomains(),
    buildEndpoints(),
    buildFingerprint(),
    buildJSFiles(),
    buildMethods(),
  ].join('');
  document.getElementById('raw-json').textContent = JSON.stringify(RAW, null, 2);
}}

init();
</script>
</body>
</html>"""


def export_html(data: Any, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _serialize(data)
    if not isinstance(payload, dict):
        payload = {"data": payload}
    payload["_meta"] = {
        "tool":     "Prothos",
        "exported": datetime.now(timezone.utc).isoformat(),
        "version":  "1.0.0",
        "target":   payload.get("target", ""),
    }
    html = _build_html(payload)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    size = path.stat().st_size // 1024
    console.print(f"[dim][+] HTML report → {path} ({size}KB)[/dim]")
    return path


def export_html_multi(reports: dict[str, Any], path: str | Path, **kwargs) -> Path:
    return export_html(reports, path, **kwargs)