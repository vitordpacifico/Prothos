import re
from dataclasses import dataclass, field
from typing import Optional

RULES: list[tuple[str, str, str, str, str]] = [

    ("sqli_mysql",    r"you have an error in your sql syntax|mysql_fetch|mysql_num_rows",
                      "MySQL Error",            "critical", "sqli"),
    ("sqli_postgres", r"pg_query\(\)|postgresql.*error|unterminated quoted string",
                      "PostgreSQL Error",       "critical", "sqli"),
    ("sqli_mssql",    r"microsoft ole db|unclosed quotation mark|sqlserver|mssql_query|"
                      r"WAITFOR DELAY|xp_cmdshell",
                      "MSSQL Error",            "critical", "sqli"),
    ("sqli_oracle",   r"ORA-\d{4,5}|oracle.*error|quoted string not properly terminated",
                      "Oracle Error",           "critical", "sqli"),
    ("sqli_sqlite",   r"SQLiteException|sqlite3\.|no such table|unrecognized token",
                      "SQLite Error",           "critical", "sqli"),
    ("sqli_generic",  r"sql syntax|syntax error.*sql|invalid sql|sql command",
                      "Generic SQL Error",      "high",     "sqli"),
    ("sqli_java",     r"com\.mysql\.jdbc|org\.postgresql|java\.sql\.|hibernate",
                      "Java SQL Stack",         "high",     "sqli"),

    ("trace_python",  r"traceback \(most recent call last\)|File \".*\.py\", line \d+",
                      "Python Traceback",       "high",     "stack_trace"),
    ("trace_java",    r"at [a-z][\w\.]+\([A-Z]\w+\.java:\d+\)|java\.lang\.\w+Exception",
                      "Java Stack Trace",       "high",     "stack_trace"),
    ("trace_php",     r"Fatal error:|Parse error:|Warning:.*on line \d+|"
                      r"Stack trace:|#\d+ [A-Z].*\.php\(\d+\)",
                      "PHP Error",              "high",     "stack_trace"),
    ("trace_net",     r"System\.\w+Exception|at System\.|\.NET Framework",
                      ".NET Exception",         "high",     "stack_trace"),
    ("trace_ruby",    r"\w+Error \(.*\):|from .*\.rb:\d+:in",
                      "Ruby Exception",         "high",     "stack_trace"),
    ("trace_node",    r"at Object\.<anonymous>|at Module\._compile|node_modules/",
                      "Node.js Stack",          "high",     "stack_trace"),
    ("trace_generic", r"exception|unhandled error|internal error|runtime error",
                      "Generic Exception",      "medium",   "stack_trace"),

    ("secret_aws",    r"AKIA[0-9A-Z]{16}",
                      "AWS Access Key",         "critical", "secret"),
    ("secret_privkey",r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
                      "Private Key",            "critical", "secret"),
    ("secret_google", r"AIza[0-9A-Za-z_\-]{35}",
                      "Google API Key",         "critical", "secret"),
    ("secret_github", r"gh[pousr]_[A-Za-z0-9_]{36,}",
                      "GitHub Token",           "critical", "secret"),
    ("secret_jwt",    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
                      "JWT Token",              "high",     "secret"),
    ("secret_generic",r'(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*["\']([^"\']{8,})["\']',
                      "Hardcoded Secret",       "high",     "secret"),
    ("secret_connstr", r"(?:mongodb|postgresql|mysql|redis|amqp)://[^\s\"'<>]+",
                      "Connection String",      "critical", "secret"),

    ("path_unix",     r"root:.*:/bin/|/etc/passwd|/etc/shadow",
                      "/etc/passwd Leak",       "critical", "lfi"),
    ("path_windows",  r"[Cc]:\\[Ww]indows\\|[Cc]:\\[Uu]sers\\|\[boot loader\]",
                      "Windows Path Leak",      "high",     "lfi"),
    ("path_generic",  r"/var/www/|/home/\w+/|/usr/local/",
                      "Unix Path Disclosure",   "medium",   "path_disclosure"),

    ("info_phpinfo",  r"phpinfo\(\)|PHP Version.*<td|php_uname",
                      "PHPInfo Exposed",        "high",     "info_disclosure"),
    ("info_debug",    r'"debug"\s*:\s*true|debug.?mode.?(?:on|enabled|true)',
                      "Debug Mode On",          "medium",   "info_disclosure"),
    ("info_version",  r'"version"\s*:\s*"[\d\.]+"|server:\s*[\w/]+[\d\.]+',
                      "Version Disclosed",      "low",      "info_disclosure"),
    ("info_dirlist",  r"index of /|parent directory|directory listing",
                      "Directory Listing",      "high",     "info_disclosure"),
    ("info_default",  r"welcome to nginx|apache2 default page|it works!|"
                      r"iis windows server",
                      "Default Server Page",    "low",      "info_disclosure"),
    ("info_env",      r"APP_ENV|APP_KEY|DB_PASSWORD|DATABASE_URL|SECRET_KEY",
                      "Env Variables Leaked",   "critical", "info_disclosure"),

    ("ssrf_aws",      r"ami-id|instance-id|iam.*security-credentials|"
                      r"169\.254\.169\.254",
                      "SSRF AWS Metadata",      "critical", "ssrf"),
    ("ssrf_gcp",      r"computeMetadata|metadata\.google\.internal",
                      "SSRF GCP Metadata",      "critical", "ssrf"),

    ("xss_script",    r"<script>alert\(1\)</script>",
                      "XSS Reflected",          "high",     "xss"),
    ("xss_attr",      r"onerror=alert\(1\)|onload=alert\(1\)|onfocus=alert\(1\)",
                      "XSS Attribute",          "high",     "xss"),
    ("xss_svg",       r"<svg[^>]*onload=",
                      "XSS SVG",                "high",     "xss"),

    ("ssti_math",     r"^49$|^49\s|\b49\b.*7\*7",
                      "SSTI {{7*7}}=49",         "critical", "ssti"),
    ("ssti_config",   r"\{.*'SECRET_KEY'|engine.*jinja|tornado\.template",
                      "SSTI Config Leak",        "critical", "ssti"),

    ("cmd_unix",      r"uid=\d+\(\w+\)\s+gid=\d+",
                      "Command Injection (id)",  "critical", "cmdi"),
    ("cmd_win",       r"Volume Serial Number|Directory of [A-Z]:\\",
                      "Command Injection (dir)", "critical", "cmdi"),

    ("auth_bypass",   r"\"role\"\s*:\s*\"admin\"|\"admin\"\s*:\s*true|"
                      r"\"isAdmin\"\s*:\s*true",
                      "Admin Role in Response",  "high",     "auth"),
    ("auth_token",    r"\"access_token\"\s*:|\"refresh_token\"\s*:|"
                      r"\"id_token\"\s*:",
                      "Token in Response",       "medium",   "auth"),

    ("http_cors",     r"access-control-allow-origin: \*",
                      "CORS Wildcard",           "medium",   "http"),
    ("http_options",  r"allow: .*TRACE|allow: .*DEBUG",
                      "Dangerous Methods",       "medium",   "http"),
]

@dataclass
class AnalysisResult:
    rule_id:   str
    label:     str
    severity:  str
    category:  str
    evidence:  str        = ""
    location:  str        = "body"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ResponseAnalysis:
    url:      str         = ""
    status:   int         = 0
    issues:   list[AnalysisResult] = field(default_factory=list)

    @property
    def critical(self) -> list[AnalysisResult]:
        return [i for i in self.issues if i.severity == "critical"]

    @property
    def high(self) -> list[AnalysisResult]:
        return [i for i in self.issues if i.severity == "high"]

    @property
    def categories(self) -> set[str]:
        return {i.category for i in self.issues}

    @property
    def has_critical(self) -> bool:
        return bool(self.critical)

    def to_dict(self) -> dict:
        return {
            "url":      self.url,
            "status":   self.status,
            "issues":   [i.to_dict() for i in self.issues],
            "critical": len(self.critical),
            "high":     len(self.high),
        }

def analyze_response(
    response:        dict,
    *,
    check_headers:   bool = True,
    check_body:      bool = True,
    max_body:        int  = 50_000,
    extra_rules:     list[tuple] = None,
) -> ResponseAnalysis:

    url     = response.get("url", "")
    status  = response.get("status", 0)
    body    = response.get("text", "")[:max_body]
    headers = response.get("headers", {})

    headers_str = "\n".join(
        f"{k.lower()}: {v.lower()}"
        for k, v in (headers.items() if isinstance(headers, dict) else [])
    )

    analysis = ResponseAnalysis(url=url, status=status)
    seen:    set[str] = set()
    rules    = RULES + (extra_rules or [])

    for rule_id, pattern, label, severity, category in rules:
        if rule_id in seen:
            continue

        if check_body and body:
            m = re.search(pattern, body, re.IGNORECASE | re.MULTILINE)
            if m:
                evidence = m.group(0)[:120].strip()
                analysis.issues.append(AnalysisResult(
                    rule_id=rule_id,
                    label=label,
                    severity=severity,
                    category=category,
                    evidence=evidence,
                    location="body",
                ))
                seen.add(rule_id)
                continue

        if check_headers and headers_str:
            m = re.search(pattern, headers_str, re.IGNORECASE)
            if m:
                evidence = m.group(0)[:120].strip()
                analysis.issues.append(AnalysisResult(
                    rule_id=rule_id,
                    label=label,
                    severity=severity,
                    category=category,
                    evidence=evidence,
                    location="header",
                ))
                seen.add(rule_id)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    analysis.issues.sort(key=lambda x: sev_order.get(x.severity, 4))

    return analysis

def analyze_batch(
    responses: list[dict],
    **kwargs,
) -> list[ResponseAnalysis]:
    return [analyze_response(r, **kwargs) for r in responses if r]


def quick_check(response: dict) -> list[str]:
    return [i.label for i in analyze_response(response).issues]