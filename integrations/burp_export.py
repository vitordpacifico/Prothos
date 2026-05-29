import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.sax.saxutils import escape
from rich.console import Console

console = Console()


def _as_dict(report: Any) -> dict:
    if hasattr(report, "to_dict"):
        return report.to_dict()
    if isinstance(report, dict):
        return report
    return {}


def _findings(data: dict) -> list[dict]:
    items = data.get("findings_detail") or data.get("findings") or []
    return [f for f in items if isinstance(f, dict)]


def _collect_urls(data: dict) -> list[dict]:
    entries = []
    seen = set()

    for f in _findings(data):
        url = f.get("url") or f.get("target")
        if url and url not in seen:
            seen.add(url)
            entries.append({
                "url": url,
                "method": (f.get("extra") or {}).get("method", "GET"),
                "comment": f"{f.get('severity', 'info')} - {f.get('title') or f.get('module', '')}",
            })

    for key in ("endpoints", "urls", "subdomains"):
        for item in data.get(key, []) or []:
            url = item if isinstance(item, str) else (item.get("url") or item.get("domain") if isinstance(item, dict) else None)
            if url and url not in seen:
                seen.add(url)
                entries.append({"url": url, "method": "GET", "comment": key})

    return entries


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8", "replace")).decode()


def _raw_request(method: str, parsed) -> str:
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    host = parsed.netloc
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0 (compatible; Prothos/1.0)\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )


def _build_item(entry: dict) -> str:
    url = entry["url"]
    parsed = urlparse(url if "://" in url else f"http://{url}")
    protocol = parsed.scheme or "http"
    host = parsed.hostname or ""
    port = parsed.port or (443 if protocol == "https" else 80)
    method = entry.get("method", "GET")
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    ts = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
    request_b64 = _b64(_raw_request(method, parsed))

    return (
        "  <item>\n"
        f"    <time>{escape(ts)}</time>\n"
        f"    <url><![CDATA[{url}]]></url>\n"
        f"    <host ip=\"\">{escape(host)}</host>\n"
        f"    <port>{port}</port>\n"
        f"    <protocol>{protocol}</protocol>\n"
        f"    <method><![CDATA[{method}]]></method>\n"
        f"    <path><![CDATA[{path}]]></path>\n"
        "    <extension>null</extension>\n"
        f"    <request base64=\"true\"><![CDATA[{request_b64}]]></request>\n"
        "    <status></status>\n"
        "    <responselength>0</responselength>\n"
        "    <mimetype></mimetype>\n"
        "    <response base64=\"true\"><![CDATA[]]></response>\n"
        f"    <comment><![CDATA[{escape(entry.get('comment', ''))}]]></comment>\n"
        "  </item>"
    )


def run_burp_export(report: Any, output_path: str) -> str:
    data = _as_dict(report)
    entries = _collect_urls(data)

    console.print(f"\n[bold red][*][/bold red] Burp Suite export → [bold white]{output_path}[/bold white]")
    console.print(f"[dim]    Sitemap items: {len(entries)}[/dim]")

    items = "\n".join(_build_item(e) for e in entries)
    xml = (
        "<?xml version=\"1.0\"?>\n"
        "<!-- exported by Prothos -->\n"
        "<items burpVersion=\"2023.1\" exportTime=\""
        + datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
        + "\">\n"
        + items
        + ("\n" if items else "")
        + "</items>\n"
    )

    try:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(xml)
        console.print(f"[dim][+] Saved to {output_path}[/dim]")
    except OSError as e:
        console.print(f"[red][!] Failed to save: {e}[/red]")

    return output_path
