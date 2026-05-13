"""
CORS misconfiguration detection — expanded coverage.
"""
import re
from urllib.parse import urlparse


def build_cors_origins(target_url: str) -> list:
    """Build targeted CORS origin probes from the actual target domain."""
    generic = [
        "https://evil.example.com",
        "https://attacker.com",
        "null",
        "https://evil.com",
        "http://evil.example.com",
    ]
    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc.lower().split(":")[0]
        base = domain.lstrip("www.")
        parts = base.split(".")
        if len(parts) >= 2:
            tld  = ".".join(parts[-2:])
            name = parts[-2]
            domain_specific = [
                f"https://evil.{tld}",
                f"https://attacker.{tld}",
                f"https://evil-{name}.com",
                f"https://{tld}.evil.com",
                f"https://{name}evil.com",
                f"https://{name}.evil.com",
                f"http://{tld}",
                f"https://{tld}:8443",
                f"https://{tld}:3000",
            ]
            return generic + domain_specific
    except Exception as _e:
        pass
    return generic


CORS_TEST_ORIGINS = [
    "https://evil.example.com",
    "https://attacker.com",
    "null",
    "https://evil.com",
    "http://evil.example.com",
    "https://evil.example.com.attacker.com",
]


def analyze_cors(headers, sent_origin: str, target_url: str = "") -> list:
    """Analyse CORS response headers for all known misconfiguration patterns."""
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    acam = headers.get("Access-Control-Allow-Methods", "")
    acah = headers.get("Access-Control-Allow-Headers", "")
    vary = headers.get("Vary", "")

    findings = []
    has_creds = acac.lower() == "true"

    if acao == "*":
        if has_creds:
            findings.append({
                "issue": "Wildcard origin with credentials",
                "severity": "high",
                "detail": "ACAO: * with ACAC: true. Browsers may allow credentialed cross-origin requests.",
                "cvss": 8.1,
            })
        else:
            findings.append({
                "issue": "Wildcard CORS origin",
                "severity": "info",
                "detail": "Public API with wildcard — only a problem if sensitive data is returned.",
                "cvss": 0,
            })
        return findings

    if acao and acao == sent_origin:
        if has_creds:
            findings.append({
                "issue": "Reflected origin with credentials allowed",
                "severity": "critical",
                "detail": (
                    f"Server reflects Origin: {sent_origin} with ACAC: true. "
                    "Attacker site can read authenticated API responses cross-origin."
                ),
                "cvss": 9.3,
                "poc": f"fetch('{target_url}', {{credentials:'include'}}) from {sent_origin} returns full auth response.",
            })
        else:
            findings.append({
                "issue": "Reflected origin without credentials",
                "severity": "medium",
                "detail": (
                    f"Server reflects Origin: {sent_origin} without credentials. "
                    "Non-credentialed data may be exposed."
                ),
                "cvss": 5.4,
            })

    if sent_origin == "null" and acao == "null":
        if has_creds:
            findings.append({
                "issue": "Null origin with credentials",
                "severity": "critical",
                "detail": (
                    "ACAO: null + ACAC: true. Sandboxed iframes use null origin — "
                    "attacker can exfiltrate credentialed responses via sandboxed iframe."
                ),
                "cvss": 9.0,
            })
        else:
            findings.append({
                "issue": "Null origin allowed",
                "severity": "medium",
                "detail": "ACAO: null. Sandboxed iframes can read non-credentialed responses.",
                "cvss": 5.0,
            })

    dangerous_methods = {"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"}
    if acam:
        allowed = {m.strip().upper() for m in acam.split(",")}
        risky = allowed & dangerous_methods
        if risky:
            findings.append({
                "issue": f"Dangerous methods cross-origin: {', '.join(risky)}",
                "severity": "medium",
                "detail": f"ACAM includes {risky} — state-changing requests may be possible cross-origin.",
                "cvss": 6.5,
            })

    if acah and "authorization" in acah.lower() and has_creds:
        findings.append({
            "issue": "Authorization header allowed cross-origin with credentials",
            "severity": "high",
            "detail": "ACAH includes Authorization with ACAC: true — cross-origin token theft possible.",
            "cvss": 7.5,
        })

    if acao and acao != "*" and "origin" not in vary.lower():
        findings.append({
            "issue": "Missing Vary: Origin header",
            "severity": "low",
            "detail": "No Vary: Origin — CDN may cache and serve permissive CORS response to all clients.",
            "cvss": 3.1,
        })

    return sorted(findings, key=lambda f: f.get("cvss", 0), reverse=True)


def get_cors_severity(findings: list) -> str:
    if not findings:
        return "none"
    top = max(f.get("cvss", 0) for f in findings)
    if top >= 9.0: return "critical"
    if top >= 7.0: return "high"
    if top >= 4.0: return "medium"
    if top > 0:    return "low"
    return "info"
