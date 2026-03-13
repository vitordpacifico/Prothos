import re
import socket
import ssl
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()

@dataclass
class FingerprintResult:
    target:      str
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status_code: Optional[int]   = None
    ip:          Optional[str]   = None
    server:      Optional[str]   = None
    powered_by:  Optional[str]   = None
    content_type:Optional[str]   = None
    waf:         list[str]       = field(default_factory=list)
    cdn:         list[str]       = field(default_factory=list)
    frameworks:  list[str]       = field(default_factory=list)
    backend:     list[str]       = field(default_factory=list)
    cms:         list[str]       = field(default_factory=list)
    languages:   list[str]       = field(default_factory=list)
    databases:   list[str]       = field(default_factory=list)
    cloud:       list[str]       = field(default_factory=list)
    security_headers: dict       = field(default_factory=dict)
    interesting_headers: dict    = field(default_factory=dict)
    ssl_info:    dict            = field(default_factory=dict)
    cookies:     list[dict]      = field(default_factory=list)
    raw_headers: dict            = field(default_factory=dict)
    errors:      list[str]       = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

SIGNATURES: dict[str, list[tuple[str, str, str]]] = {

    "waf": [
        ("header:server",               r"cloudflare",              "Cloudflare"),
        ("header:cf-ray",               r".",                        "Cloudflare"),
        ("header:x-sucuri-id",          r".",                        "Sucuri"),
        ("header:x-firewall-protection",r".",                        "Sucuri"),
        ("header:server",               r"awselb|aws",               "AWS WAF"),
        ("header:x-amzn-requestid",     r".",                        "AWS"),
        ("header:x-cdn",                r"imperva|incapsula",        "Imperva/Incapsula"),
        ("header:x-iinfo",              r".",                        "Imperva/Incapsula"),
        ("header:x-denied-reason",      r".",                        "WAF Block"),
        ("header:server",               r"barracuda",                "Barracuda WAF"),
        ("header:x-datadome",           r".",                        "DataDome"),
        ("header:server",               r"f5 big-ip|big-ip",         "F5 BIG-IP"),
        ("header:x-waf-event-info",     r".",                        "Reblaze"),
        ("header:x-mod-pagespeed",      r".",                        "ModPageSpeed"),
        ("html",                        r"waf\.akamai\.com",         "Akamai WAF"),
        ("html",                        r"access denied.*cloudflare","Cloudflare Block"),
        ("html",                        r"ray id:",                  "Cloudflare Block"),
    ],

    "cdn": [
        ("header:server",               r"akamai",                   "Akamai"),
        ("header:x-akamai-transformed", r".",                        "Akamai"),
        ("header:via",                  r"akamai",                   "Akamai"),
        ("header:x-fastly-request-id",  r".",                        "Fastly"),
        ("header:via",                  r"fastly",                   "Fastly"),
        ("header:x-cache",              r"cloudfront",               "AWS CloudFront"),
        ("header:x-amz-cf-id",          r".",                        "AWS CloudFront"),
        ("header:server",               r"cloudfront",               "AWS CloudFront"),
        ("header:x-azure-ref",          r".",                        "Azure CDN"),
        ("header:x-ms-request-id",      r".",                        "Azure"),
        ("header:x-cache",              r"varnish",                  "Varnish"),
        ("header:x-varnish",            r".",                        "Varnish"),
        ("header:x-bunny-cache",        r".",                        "BunnyCDN"),
        ("header:server",               r"keycdn",                   "KeyCDN"),
        ("header:via",                  r"1\.1 google",              "Google CDN"),
    ],

    "framework": [
        ("html",    r"react(?:\.js|dom|[-/])",                      "React"),
        ("html",    r"vue(?:\.js|[-/\s])",                          "Vue.js"),
        ("html",    r"angular(?:\.js|[-/\s]|/core)",                "Angular"),
        ("html",    r"next(?:js|[-/]data|/_next/)",                 "Next.js"),
        ("html",    r"nuxt(?:js|[-/]|\.js)",                        "Nuxt.js"),
        ("html",    r"svelte(?:[-/.]|kit)",                         "Svelte"),
        ("html",    r"ember(?:\.js|[-/])",                          "Ember.js"),
        ("html",    r"backbone(?:\.js|[-/])",                       "Backbone.js"),
        ("html",    r"jquery(?:\.js|[-/.]|\.min)",                  "jQuery"),
        ("html",    r"bootstrap(?:\.css|\.js|[-/.])",               "Bootstrap"),
        ("html",    r"tailwind(?:css|\.css|[-/.])",                 "Tailwind CSS"),
        ("html",    r"__remix_manifest|window\.__remixContext",     "Remix"),
        ("html",    r"gatsby(?:[-/]|\.js|ssr)",                     "Gatsby"),
        ("html",    r"inertia(?:js|[-/.])",                         "Inertia.js"),
        ("html",    r"astro(?:[-/.]|\.build)",                      "Astro"),
    ],

    "backend": [
        ("header:x-powered-by",         r"php",                     "PHP"),
        ("header:x-powered-by",         r"asp\.net",                "ASP.NET"),
        ("header:x-powered-by",         r"express",                 "Express.js"),
        ("header:x-powered-by",         r"next\.js",                "Next.js"),
        ("header:server",               r"nginx",                   "Nginx"),
        ("header:server",               r"apache",                  "Apache"),
        ("header:server",               r"iis|microsoft-iis",       "IIS"),
        ("header:server",               r"lighttpd",                "Lighttpd"),
        ("header:server",               r"caddy",                   "Caddy"),
        ("header:server",               r"gunicorn",                "Gunicorn (Python)"),
        ("header:server",               r"unicorn",                 "Unicorn (Ruby)"),
        ("header:server",               r"jetty",                   "Jetty (Java)"),
        ("header:server",               r"tomcat",                  "Tomcat (Java)"),
        ("header:server",               r"werkzeug",                "Werkzeug (Python)"),
        ("header:server",               r"openresty",               "OpenResty"),
        ("header:x-generator",          r".",                        "Generator Header"),
        ("cookie:laravel_session",      r".",                        "Laravel (PHP)"),
        ("cookie:csrftoken",            r".",                        "Django (Python)"),
        ("cookie:rack.session",         r".",                        "Rack (Ruby)"),
        ("cookie:jsessionid",           r".",                        "Java/Spring"),
        ("cookie:phpsessid",            r".",                        "PHP"),
        ("cookie:asp.net_sessionid",    r".",                        "ASP.NET"),
    ],

    "cms": [
        ("html",    r"/wp-content/|/wp-includes/|wp-json",          "WordPress"),
        ("html",    r"drupal(?:\.js|\.css|settings)",               "Drupal"),
        ("html",    r"joomla(?:\.js|!)",                            "Joomla"),
        ("html",    r"shopify(?:cdn|\.com|\.js)",                   "Shopify"),
        ("html",    r"cdn\.shopify\.com",                           "Shopify"),
        ("html",    r"wix\.com|wixsite\.com",                       "Wix"),
        ("html",    r"squarespace(?:cdn|\.com)",                    "Squarespace"),
        ("html",    r"ghost(?:[-/.]|cms)",                          "Ghost"),
        ("html",    r"webflow(?:\.io|\.js|css)",                    "Webflow"),
        ("html",    r"magento(?:[-/.]|\.js)",                       "Magento"),
        ("html",    r"prestashop",                                  "PrestaShop"),
        ("html",    r"typo3",                                       "TYPO3"),
        ("html",    r"contentful",                                  "Contentful"),
        ("html",    r"strapi",                                      "Strapi"),
        ("header:x-pingback",           r"xmlrpc\.php",             "WordPress (xmlrpc)"),
        ("header:x-drupal-cache",       r".",                        "Drupal"),
    ],

    "language": [
        ("header:x-powered-by",         r"php/(\d[\d.]+)",          "PHP"),
        ("header:x-powered-by",         r"asp\.net",                "C# / ASP.NET"),
        ("header:content-type",         r"charset=utf-8",           "UTF-8"),
        ("html",                        r"/__pycache__|\.pyc",       "Python"),
        ("html",                        r"rails|ruby on rails",      "Ruby on Rails"),
        ("html",                        r"laravel|illuminate\\",     "PHP/Laravel"),
        ("html",                        r"spring(?:boot|mvc|[-/])",  "Java/Spring"),
        ("html",                        r"\.go\b|golang",            "Go"),
        ("html",                        r"node(?:\.js|[-/])|express","Node.js"),
    ],

    "cloud": [
        ("header:x-amzn-requestid",     r".",                        "AWS"),
        ("header:x-amz-request-id",     r".",                        "AWS S3"),
        ("header:x-azure-ref",          r".",                        "Azure"),
        ("header:x-ms-request-id",      r".",                        "Azure"),
        ("header:x-goog-request-id",    r".",                        "GCP"),
        ("header:alt-svc",              r"h3.*googleapi|quic",       "GCP"),
        ("header:server",               r"heroku",                   "Heroku"),
        ("header:x-heroku-request-id",  r".",                        "Heroku"),
        ("header:x-vercel",             r".",                        "Vercel"),
        ("header:x-vercel-id",          r".",                        "Vercel"),
        ("header:server",               r"netlify",                  "Netlify"),
        ("header:x-nf-request-id",      r".",                        "Netlify"),
        ("header:fly-request-id",       r".",                        "Fly.io"),
        ("header:x-railway-request-id", r".",                        "Railway"),
        ("header:x-render-origin-server",r".",                       "Render"),
    ],
}

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "expect-ct",
    "cache-control",
    "pragma",
]

INTERESTING_HEADERS = [
    "x-request-id",
    "x-trace-id",
    "x-correlation-id",
    "x-internal-ip",
    "x-real-ip",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-original-url",
    "x-rewrite-url",
    "x-backend",
    "x-cluster-client-ip",
    "x-envoy-upstream-service-time",
    "x-kong-upstream-latency",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-api-version",
    "x-app-version",
    "x-build-id",
    "x-deployment-id",
    "x-region",
    "x-datacenter",
    "x-pod-name",
    "x-node-id",
    "x-instance-id",
    "etag",
    "last-modified",
    "age",
    "vary",
    "link",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
]

def _resolve_ip(target: str) -> Optional[str]:
    try:
        host = urlparse(target).hostname or target
        return socket.gethostbyname(host)
    except Exception:
        return None


def _get_ssl_info(target: str) -> dict:
    """Extrai info do certificado SSL: issuer, expiry, SANs, wildcards."""
    try:
        parsed = urlparse(target)
        if parsed.scheme != "https":
            return {}
        host = parsed.hostname
        port = parsed.port or 443
        ctx  = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=8),
                             server_hostname=host) as ssock:
            cert = ssock.getpeercert()
        return {
            "subject":    dict(x[0] for x in cert.get("subject", [])),
            "issuer":     dict(x[0] for x in cert.get("issuer", [])),
            "notAfter":   cert.get("notAfter"),
            "notBefore":  cert.get("notBefore"),
            "version":    cert.get("version"),
            "san":        [v for _, v in cert.get("subjectAltName", [])],
        }
    except Exception:
        return {}


def _match_signatures(
    category: str,
    headers_lower: dict,
    html: str,
    cookies_lower: dict,
) -> list[str]:
    found: list[str] = []
    seen:  set[str]  = set()

    for (field, pattern, label) in SIGNATURES.get(category, []):
        if label in seen:
            continue

        text = ""
        if field.startswith("header:"):
            text = headers_lower.get(field[7:], "")
        elif field == "html":
            text = html
        elif field.startswith("cookie:"):
            text = cookies_lower.get(field[7:], "")

        if text and re.search(pattern, text, re.IGNORECASE):
            found.append(label)
            seen.add(label)

    return found


def _audit_security_headers(headers_lower: dict) -> dict:
    return {h: headers_lower.get(h, "MISSING") for h in SECURITY_HEADERS}


def _collect_interesting_headers(headers_lower: dict) -> dict:
    return {h: v for h in INTERESTING_HEADERS if (v := headers_lower.get(h))}


def _parse_cookies(response: requests.Response) -> list[dict]:
    result = []
    for cookie in response.cookies:
        result.append({
            "name":     cookie.name,
            "value":    cookie.value[:40] + "..." if cookie.value and len(cookie.value) > 40 else cookie.value,
            "domain":   cookie.domain,
            "path":     cookie.path,
            "secure":   cookie.secure,
            "httponly": cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie._rest).lower(),
            "samesite": cookie._rest.get("SameSite", "Not Set"),
        })
    return result

def _display_results(r: FingerprintResult):
    console.print()
    console.print(Panel(
        f"[bold white]{r.target}[/bold white]  "
        f"[dim]HTTP {r.status_code}[/dim]  "
        f"[dim]IP: {r.ip or 'unresolved'}[/dim]  "
        f"[dim]{r.timestamp}[/dim]",
        title="[bold red]Tech Fingerprint[/bold red]",
        border_style="red",
    ))

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Category",  style="bold cyan",  width=20)
    table.add_column("Detected",  style="white")

    def row(cat, items):
        if items:
            val = "  ".join(f"[green]{i}[/green]" for i in items) if isinstance(items, list) else f"[green]{items}[/green]"
            table.add_row(cat, val)

    row("Server",      r.server)
    row("Powered By",  r.powered_by)
    row("WAF",         r.waf)
    row("CDN",         r.cdn)
    row("Cloud",       r.cloud)
    row("Backend",     r.backend)
    row("Framework",   r.frameworks)
    row("CMS",         r.cms)
    row("Language",    r.languages)
    row("IP",          r.ip)
    row("Content-Type",r.content_type)

    console.print(table)

    if r.ssl_info:
        ssl_table = Table(show_header=True, header_style="bold yellow", border_style="dim")
        ssl_table.add_column("SSL Field", style="bold cyan", width=20)
        ssl_table.add_column("Value",     style="white")
        ssl_table.add_row("Issuer",   str(r.ssl_info.get("issuer", {}).get("organizationName", "?")))
        ssl_table.add_row("Expires",  str(r.ssl_info.get("notAfter", "?")))
        ssl_table.add_row("SANs",     "  ".join(r.ssl_info.get("san", [])[:8]))
        console.print(ssl_table)

    sec_table = Table(show_header=True, header_style="bold yellow", border_style="dim")
    sec_table.add_column("Security Header", style="bold cyan", width=35)
    sec_table.add_column("Status",          style="white")
    for h, v in r.security_headers.items():
        style = "[red]MISSING[/red]" if v == "MISSING" else f"[green]{v[:60]}[/green]"
        sec_table.add_row(h, style)
    console.print(sec_table)

    if r.interesting_headers:
        ih_table = Table(show_header=True, header_style="bold magenta", border_style="dim")
        ih_table.add_column("Interesting Header", style="bold cyan", width=35)
        ih_table.add_column("Value",              style="yellow")
        for h, v in r.interesting_headers.items():
            ih_table.add_row(h, v[:80])
        console.print(ih_table)

    if r.cookies:
        ck_table = Table(show_header=True, header_style="bold blue", border_style="dim")
        ck_table.add_column("Cookie",    style="bold cyan",  width=25)
        ck_table.add_column("Secure",    style="white",      width=8)
        ck_table.add_column("HttpOnly",  style="white",      width=10)
        ck_table.add_column("SameSite",  style="white",      width=12)
        ck_table.add_column("Value",     style="dim",        width=35)
        for ck in r.cookies:
            secure   = "[green]✓[/green]" if ck["secure"]   else "[red]✗[/red]"
            httponly = "[green]✓[/green]" if ck["httponly"]  else "[red]✗[/red]"
            samesite = ck["samesite"] or "[dim]Not Set[/dim]"
            ck_table.add_row(ck["name"], secure, httponly, samesite, str(ck["value"]))
        console.print(ck_table)

    console.print()

def run_tech_fingerprint(
    target: str,
    timeout: int = 10,
    proxy: Optional[str] = None,
    save_json: Optional[str] = None,
    user_agent: str = "Mozilla/5.0 (compatible; Prothos/1.0)",
) -> FingerprintResult:
   
    result = FingerprintResult(target=target)
    console.print(f"\n[bold red][*][/bold red] Fingerprinting [bold white]{target}[/bold white]...")

    result.ip = _resolve_ip(target)

    result.ssl_info = _get_ssl_info(target)

    try:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        resp = requests.get(
            target,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            proxies=proxies,
            headers={"User-Agent": user_agent},
        )
    except RequestException as e:
        result.errors.append(str(e))
        console.print(f"[red][!] Request failed: {e}[/red]")
        return result

    result.status_code  = resp.status_code
    result.raw_headers  = dict(resp.headers)
    result.content_type = resp.headers.get("content-type", "")

    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
    html          = resp.text.lower()
    cookies_lower = {c.name.lower(): c.value.lower() for c in resp.cookies}

    result.server     = resp.headers.get("server")
    result.powered_by = resp.headers.get("x-powered-by")

    for category in ("waf", "cdn", "framework", "backend", "cms", "language", "cloud"):
        matches = _match_signatures(category, headers_lower, html, cookies_lower)
        getattr(result, {"framework": "frameworks", "language": "languages"}.get(category, category)).extend(matches)

    result.security_headers    = _audit_security_headers(headers_lower)
    result.interesting_headers = _collect_interesting_headers(headers_lower)

    result.cookies = _parse_cookies(resp)

    _display_results(result)

    if save_json:
        try:
            with open(save_json, "w") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            result.errors.append(f"save_json: {e}")

    return result