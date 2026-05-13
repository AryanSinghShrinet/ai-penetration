"""
Passive Intelligence Layer for AI-Pentester

Analyzes HTML, Headers, Cookies, and JS without aggressive fuzzing.

EXTENDED: Now includes security header analysis, CSP weakness detection,
JWT misconfiguration checks, and CORS analysis.
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict


@dataclass
class SecurityHeaderIssue:
    """Represents a security header finding."""
    header: str
    issue: str
    severity: str  # high, medium, low, info
    recommendation: str


@dataclass  
class PassiveFindings:
    """Container for all passive scan findings."""
    security_headers: List[SecurityHeaderIssue]
    csp_issues: List[str]
    cors_issues: List[str]
    jwt_issues: List[str]
    cookie_issues: List[str]
    information_disclosure: List[str]
    
    def to_dict(self) -> Dict:
        return {
            "security_headers": [asdict(h) for h in self.security_headers],
            "csp_issues": self.csp_issues,
            "cors_issues": self.cors_issues,
            "jwt_issues": self.jwt_issues,
            "cookie_issues": self.cookie_issues,
            "information_disclosure": self.information_disclosure,
        }


# ============================================================================
# Security Header Checks
# ============================================================================

# Headers that should be present for security
REQUIRED_SECURITY_HEADERS = {
    "X-Frame-Options": {
        "severity": "medium",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "recommendation": "Set X-Content-Type-Options: nosniff"
    },
    "X-XSS-Protection": {
        "severity": "low", 
        "recommendation": "Set X-XSS-Protection: 1; mode=block"
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "recommendation": "Set HSTS with max-age >= 31536000"
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "recommendation": "Implement a Content Security Policy"
    },
    "Referrer-Policy": {
        "severity": "low",
        "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "low",
        "recommendation": "Set Permissions-Policy to restrict features"
    },
}

# Headers that indicate information disclosure
INFO_DISCLOSURE_HEADERS = [
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "Server",
]


def check_security_headers(headers: Dict[str, str]) -> List[SecurityHeaderIssue]:
    """
    Check for missing or misconfigured security headers.
    
    Returns list of security header issues found.
    """
    issues = []
    
    # Check for missing required headers
    for header, info in REQUIRED_SECURITY_HEADERS.items():
        if header.lower() not in {k.lower() for k in headers.keys()}:
            issues.append(SecurityHeaderIssue(
                header=header,
                issue=f"Missing {header} header",
                severity=info["severity"],
                recommendation=info["recommendation"]
            ))
    
    # Check X-Frame-Options value
    xfo = headers.get("X-Frame-Options", "").upper()
    if xfo and xfo not in ["DENY", "SAMEORIGIN"]:
        issues.append(SecurityHeaderIssue(
            header="X-Frame-Options",
            issue=f"Weak value: {xfo}",
            severity="medium",
            recommendation="Use DENY or SAMEORIGIN"
        ))
    
    # Check HSTS max-age
    hsts = headers.get("Strict-Transport-Security", "")
    if hsts:
        max_age_match = re.search(r'max-age=(\d+)', hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                issues.append(SecurityHeaderIssue(
                    header="Strict-Transport-Security",
                    issue=f"max-age too low: {max_age}",
                    severity="low",
                    recommendation="Set max-age to at least 31536000 (1 year)"
                ))
    
    # Check for information disclosure headers
    for header in INFO_DISCLOSURE_HEADERS:
        if header.lower() in {k.lower() for k in headers.keys()}:
            value = headers.get(header, "")
            issues.append(SecurityHeaderIssue(
                header=header,
                issue=f"Information disclosure: {value}",
                severity="info",
                recommendation=f"Remove {header} header"
            ))
    
    return issues


def check_csp_weakness(csp_header: str) -> List[str]:
    """
    Analyze Content Security Policy for weaknesses.
    
    Checks for:
    - unsafe-inline
    - unsafe-eval
    - Wildcard sources
    - data: URI schemes
    - Missing directives
    """
    issues = []
    
    if not csp_header:
        return ["No Content-Security-Policy header present"]
    
    # Check for unsafe directives
    if "'unsafe-inline'" in csp_header:
        issues.append("CSP allows 'unsafe-inline' - enables inline script execution")
    
    if "'unsafe-eval'" in csp_header:
        issues.append("CSP allows 'unsafe-eval' - enables eval() and similar")
    
    # Check for wildcards
    if " * " in csp_header or "script-src *" in csp_header or "script-src: *" in csp_header:
        issues.append("CSP uses wildcard (*) - allows scripts from any origin")
    
    # Check for data: scheme
    if "data:" in csp_header:
        issues.append("CSP allows data: URI scheme - potential XSS vector")
    
    # Check for missing important directives
    important_directives = ["default-src", "script-src", "object-src", "base-uri"]
    for directive in important_directives:
        if directive not in csp_header:
            issues.append(f"CSP missing '{directive}' directive")
    
    # Check for report-only mode
    # (This would require checking the header name, but we just have value here)
    
    return issues


def check_cors_misconfiguration(headers: Dict[str, str], origin_tested: str = "") -> List[str]:
    """
    Check for CORS misconfigurations.
    
    Checks for:
    - Wildcard origin with credentials
    - Null origin allowed
    - Overly permissive origins
    """
    issues = []
    
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()
    
    if not acao:
        return []  # No CORS headers = not a finding
    
    # Wildcard with credentials
    if acao == "*" and acac == "true":
        issues.append("CRITICAL: CORS allows wildcard (*) origin WITH credentials")
    
    # Wildcard alone (less severe)
    if acao == "*":
        issues.append("CORS uses wildcard (*) - allows any origin")
    
    # Null origin
    if acao.lower() == "null":
        issues.append("CORS allows 'null' origin - can be exploited via sandboxed iframes")
    
    # Reflection of origin (if we tested with a specific origin)
    if origin_tested and acao == origin_tested:
        issues.append(f"CORS may be reflecting Origin header: {acao}")
    
    # Check for overly permissive methods
    acam = headers.get("Access-Control-Allow-Methods", "")
    if "DELETE" in acam or "PUT" in acam:
        if acac == "true":
            issues.append("CORS allows dangerous methods (DELETE/PUT) with credentials")
    
    return issues


def check_jwt_misconfiguration(cookies: List[str], headers: Dict[str, str]) -> List[str]:
    """
    Check for JWT-related misconfigurations.
    
    Looks for JWT tokens in cookies/headers and analyzes their properties.
    """
    issues = []
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    
    # Check cookies for JWT
    for cookie in cookies:
        if re.match(jwt_pattern, cookie):
            issues.append(f"JWT found in cookie name pattern")
    
    # Check Authorization header pattern
    auth_header = headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if re.match(jwt_pattern, token):
            # Try to decode header (base64)
            try:
                import base64
                import json
                header_part = token.split('.')[0]
                # Add padding if needed
                padding = 4 - len(header_part) % 4
                if padding != 4:
                    header_part += '=' * padding
                decoded = base64.urlsafe_b64decode(header_part)
                header_json = json.loads(decoded)
                
                alg = header_json.get("alg", "")
                if alg.lower() == "none":
                    issues.append("CRITICAL: JWT uses 'none' algorithm - no signature verification")
                elif alg.lower() in ["hs256", "hs384", "hs512"]:
                    issues.append("JWT uses symmetric algorithm (HMAC) - ensure strong secret")
                    
            except Exception as _e:
                import logging; logging.getLogger(__name__).debug(f'[recon.passive] JWT parse error: {_e}')
    
    return issues


def check_cookie_security(response) -> List[str]:
    """
    Check cookies for security flags.
    
    Checks for:
    - Missing Secure flag
    - Missing HttpOnly flag
    - Missing SameSite attribute
    """
    issues = []
    
    if not hasattr(response, 'cookies'):
        return issues
    
    for cookie in response.cookies:
        cookie_issues = []
        
        if not cookie.secure:
            cookie_issues.append("missing Secure flag")
        
        # HttpOnly check - need to look at Set-Cookie header
        # requests doesn't expose this directly, so we check headers
        
        if not cookie_issues:
            continue
            
        issues.append(f"Cookie '{cookie.name}': {', '.join(cookie_issues)}")
    
    # Also check Set-Cookie headers for more details
    set_cookie_headers = response.headers.get("Set-Cookie", "")
    if set_cookie_headers:
        for header_val in set_cookie_headers.split(','):
            if 'HttpOnly' not in header_val:
                # Extract cookie name
                match = re.match(r'^([^=]+)=', header_val.strip())
                if match:
                    name = match.group(1)
                    if f"Cookie '{name}'" not in str(issues):
                        issues.append(f"Cookie '{name}': missing HttpOnly flag")
            
            if 'SameSite' not in header_val:
                match = re.match(r'^([^=]+)=', header_val.strip())
                if match:
                    name = match.group(1)
                    issues.append(f"Cookie '{name}': missing SameSite attribute")
    
    return issues


def check_information_disclosure(response_text: str, headers: Dict[str, str]) -> List[str]:
    """
    Check for information disclosure in response.
    
    Looks for:
    - Stack traces
    - Version numbers
    - Internal paths
    - Debug information
    """
    issues = []
    
    # Stack trace patterns
    stack_patterns = [
        r'Traceback \(most recent call last\)',  # Python
        r'at .+\(.+:\d+\)',  # Java/Node
        r'#\d+ .+\(.+\) called at',  # PHP
        r'Stack trace:',
        r'Exception in thread',
    ]
    
    for pattern in stack_patterns:
        if re.search(pattern, response_text, re.I):
            issues.append("Stack trace detected in response")
            break
    
    # Version disclosure patterns
    version_patterns = [
        (r'PHP/[\d.]+', "PHP version disclosed"),
        (r'Apache/[\d.]+', "Apache version disclosed"),
        (r'nginx/[\d.]+', "nginx version disclosed"),
        (r'ASP\.NET Version:[\d.]+', "ASP.NET version disclosed"),
        (r'X-Powered-By: [\w.]+', "Technology stack disclosed"),
    ]
    
    for pattern, message in version_patterns:
        if re.search(pattern, response_text, re.I):
            issues.append(message)
    
    # Internal path patterns
    path_patterns = [
        r'[A-Z]:\\[\w\\]+',  # Windows paths
        r'/var/www/[\w/]+',  # Linux web roots
        r'/home/[\w/]+',  # Linux home dirs
    ]
    
    for pattern in path_patterns:
        if re.search(pattern, response_text):
            issues.append("Internal file path disclosed")
            break
    
    return issues


# ============================================================================
# Main Passive Analysis Function (PRESERVED - extended)
# ============================================================================

def analyze_passive(target, logger, session=None):
    """
    Layer 1: Passive Intelligence
    Analyzes HTML, Headers, Cookies, and JS without aggressive fuzzing.
    
    EXTENDED: Now includes security header checks, CSP analysis,
    CORS checks, JWT analysis, and information disclosure detection.
    """
    logger.info("  [1/6] Running Passive Intelligence Layer...")
    
    if session is None:
        session = requests.Session()

    recon_data = {
        "target": target,
        "status_code": None,
        "headers": {},
        "server": "",
        "content_type": "",
        "endpoints": set(),
        "parameters": set(),
        "forms": [],
        "cookies": [],
        "technologies": [],
        "hidden_elements": [],
        "comments": [],
        # NEW: Passive security findings
        "passive_findings": None,
    }

    response = None
    passive_findings = PassiveFindings(
        security_headers=[],
        csp_issues=[],
        cors_issues=[],
        jwt_issues=[],
        cookie_issues=[],
        information_disclosure=[],
    )
    
    try:
        response = session.get(target, timeout=30, allow_redirects=True)
        recon_data["status_code"] = response.status_code
        recon_data["headers"] = dict(response.headers)
        recon_data["content_type"] = response.headers.get("Content-Type", "")
        recon_data["cookies"] = [c.name for c in response.cookies]
        recon_data["server"] = response.headers.get("Server", "")

        # Technology hints
        header_blob = " ".join(response.headers.values()).lower()
        if "php" in header_blob: recon_data["technologies"].append("php")
        if "asp" in header_blob: recon_data["technologies"].append("asp")
        if "nginx" in header_blob: recon_data["technologies"].append("nginx")
        if "apache" in header_blob: recon_data["technologies"].append("apache")

        # AI-Powered Technology Detection
        try:
            from core.ml_analysis.scanner_core import AIVulnerabilityScanner
            ai_scanner = AIVulnerabilityScanner()
            detected_tech = ai_scanner.detect_tech_stack(response)
            for t in detected_tech:
                if t not in recon_data["technologies"]:
                    recon_data["technologies"].append(t)
        except Exception as e:
            logger.warning(f"AI Tech Detection failed: {e}")

        # ================================================================
        # NEW: Extended Security Checks
        # ================================================================
        
        # Security header analysis
        passive_findings.security_headers = check_security_headers(
            recon_data["headers"]
        )
        
        # CSP weakness analysis
        csp = recon_data["headers"].get("Content-Security-Policy", "")
        passive_findings.csp_issues = check_csp_weakness(csp)
        
        # CORS analysis
        passive_findings.cors_issues = check_cors_misconfiguration(
            recon_data["headers"]
        )
        
        # JWT analysis
        passive_findings.jwt_issues = check_jwt_misconfiguration(
            recon_data["cookies"],
            recon_data["headers"]
        )
        
        # Cookie security
        passive_findings.cookie_issues = check_cookie_security(response)
        
        # Information disclosure
        passive_findings.information_disclosure = check_information_disclosure(
            response.text,
            recon_data["headers"]
        )
        
        # Log findings summary
        total_issues = (
            len(passive_findings.security_headers) +
            len(passive_findings.csp_issues) +
            len(passive_findings.cors_issues) +
            len(passive_findings.jwt_issues) +
            len(passive_findings.cookie_issues) +
            len(passive_findings.information_disclosure)
        )
        logger.info(f"  [passive] Found {total_issues} passive security issues")
        
        # ================================================================
        # Original functionality (preserved)
        # ================================================================

        # URL parameters
        parsed = urlparse(response.url)
        for p in parse_qs(parsed.query).keys():
            recon_data["parameters"].add(p)

        # HTML parsing
        if "html" in recon_data["content_type"].lower():
            soup = BeautifulSoup(response.text, "html.parser")

            # Links
            for a in soup.find_all("a", href=True):
                recon_data["endpoints"].add(urljoin(response.url, a["href"]))

            # Forms
            for form in soup.find_all("form"):
                form_info = {
                    "action": urljoin(response.url, form.get("action", "")),
                    "method": form.get("method", "get").lower(),
                    "inputs": []
                }
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    if name:
                        form_info["inputs"].append(name)
                        recon_data["parameters"].add(name)
                        if inp.get("type") == "hidden":
                             recon_data["hidden_elements"].append({"type": "hidden_input", "name": name, "value": inp.get("value")})
                
                recon_data["forms"].append(form_info)
            
            # Comments (simple check)
            comments = re.findall(r"<!--(.*?)-->", response.text)
            recon_data["comments"] = [c.strip() for c in comments if len(c) < 200]

    except Exception as e:
        logger.error(f"Passive analysis failed: {e}")

    # Store passive findings
    recon_data["passive_findings"] = passive_findings.to_dict()
    
    # Convert sets to lists
    recon_data["endpoints"] = list(recon_data["endpoints"])
    recon_data["parameters"] = list(recon_data["parameters"])

    return recon_data, response
