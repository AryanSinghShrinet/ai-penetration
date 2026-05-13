"""
POC Generator for AI-Pentester

REFACTORED: Now uses VulnKey for canonical POC generation.
- One POC per VulnKey (no duplicates)
- Stable POC IDs using SHA256 hash
- Uses strongest evidence from knowledge base
"""

import json
import hashlib
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from core.scanner.vuln_key import VulnKey, generate_poc_id, normalize_vuln_key

# Remediation recommendations per vulnerability type
REMEDIATION_GUIDE = {
    "xss": {
        "title": "Cross-Site Scripting Prevention",
        "recommendations": [
            "Implement context-aware output encoding",
            "Use Content-Security-Policy (CSP) headers",
            "Validate and sanitize all user inputs",
            "Use HTTPOnly and Secure flags for cookies",
            "Consider using frameworks with auto-escaping (React, Angular)"
        ]
    },
    "sqli": {
        "title": "SQL Injection Prevention",
        "recommendations": [
            "Use parameterized queries / prepared statements",
            "Implement input validation with whitelist approach",
            "Apply principle of least privilege for database accounts",
            "Use stored procedures where applicable",
            "Enable WAF rules for SQL injection patterns"
        ]
    },
    "idor": {
        "title": "IDOR Prevention",
        "recommendations": [
            "Implement proper authorization checks for all object access",
            "Use indirect references (UUIDs) instead of sequential IDs",
            "Verify object ownership before returning data",
            "Implement access control at the data layer",
            "Log and monitor access patterns"
        ]
    },
    "ssrf": {
        "title": "SSRF Prevention",
        "recommendations": [
            "Whitelist allowed domains and IP ranges",
            "Block requests to internal networks (10.x, 172.16.x, 192.168.x, 127.x)",
            "Disable unnecessary URL schemes (file://, gopher://)",
            "Use a URL parser to validate and normalize URLs",
            "Implement network segmentation"
        ]
    },
    "file_upload": {
        "title": "File Upload Security",
        "recommendations": [
            "Validate file type using magic bytes, not just extension",
            "Rename uploaded files with random names",
            "Store uploads outside webroot",
            "Set proper permissions on upload directory",
            "Scan uploaded files for malware"
        ]
    },
    "cors": {
        "title": "CORS Configuration",
        "recommendations": [
            "Whitelist specific allowed origins",
            "Avoid using Access-Control-Allow-Origin: *",
            "Never reflect the Origin header without validation",
            "Be cautious with Access-Control-Allow-Credentials: true",
            "Validate and sanitize the Origin header"
        ]
    },
    "cmd_injection": {
        "title": "Command Injection Prevention",
        "recommendations": [
            "Avoid using shell commands with user input",
            "Use language-specific APIs instead of shell commands",
            "If shell is necessary, use parameterized execution",
            "Whitelist allowed characters in input",
            "Run processes with minimal privileges"
        ]
    },
    "lfi": {
        "title": "Local File Inclusion Prevention",
        "recommendations": [
            "Avoid using user input in file paths",
            "Use a whitelist of allowed files",
            "Normalize paths and check for traversal patterns",
            "Chroot the application if possible",
            "Set proper file permissions"
        ]
    }
}

# CVSS scoring guidance (ASCII-safe)
SEVERITY_CVSS = {
    "critical": {"score": "9.0-10.0", "color": "[CRITICAL]"},
    "high": {"score": "7.0-8.9", "color": "[HIGH]"},
    "medium": {"score": "4.0-6.9", "color": "[MEDIUM]"},
    "low": {"score": "0.1-3.9", "color": "[LOW]"}
}


class POCGenerator:
    """
    Generate detailed Proof of Concept documentation for vulnerabilities.
    """
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
    
    def generate(self, finding: Dict) -> Dict:
        """
        Generate POC from a finding.
        
        Args:
            finding: {
                "vuln": "xss",
                "target": "http://example.com/search",
                "payload": "...",
                "param": "q",
                "evidence": {...},
                "response": {...}
            }
        
        Returns:
            Complete POC dictionary
        """
        vuln_type = finding.get("vuln", "unknown")
        severity = self._calculate_severity(finding)
        
        # FIX POC1: The finding dict carries the *scan-root* URL in "target"
        # (e.g. http://localhost/#/) and the *actual* vulnerable endpoint inside
        # evidence["endpoint"] / evidence["vulnerable_url"] / evidence["parameter"].
        # Always prefer the specific evidence fields so every PoC points at the
        # real vulnerable URL rather than the scan root.
        evidence = finding.get("evidence", {})
        ev_endpoint = evidence.get("endpoint", "") if isinstance(evidence, dict) else ""
        ev_vuln_url = evidence.get("vulnerable_url", "") if isinstance(evidence, dict) else ""
        ev_param    = evidence.get("parameter", "") if isinstance(evidence, dict) else ""
        real_url    = ev_vuln_url or ev_endpoint or finding.get("target", "")
        real_param  = ev_param or finding.get("param", "")

        poc = {
            "id": self._generate_id(finding),
            "title": f"{self._get_vuln_name(vuln_type)} Vulnerability",
            "vulnerability_type": vuln_type,
            "severity": severity,
            "cvss_estimate": SEVERITY_CVSS.get(severity, {}).get("score", "N/A"),

            "affected_url": real_url,
            "affected_endpoint": self._extract_endpoint(real_url),
            "vulnerable_parameter": real_param,
            "payload_used": finding.get("payload", ""),
            
            "discovered_at": datetime.utcnow().isoformat(),
            
            # FIX POC1 (reporting copy): pass real_url/real_param so all PoC fields
            # point at the actual vulnerable endpoint, not the scan root URL.
            "steps_to_reproduce": self._generate_steps({**finding, "target": real_url, "param": real_param}),
            "curl_command": self._generate_curl({**finding, "target": real_url, "param": real_param}),
            "raw_request": self._generate_raw_request({**finding, "target": real_url, "param": real_param}),
            
            "evidence": finding.get("evidence", {}),
            "response_snippet": self._extract_response_snippet(finding),
            
            "impact": self._describe_impact(vuln_type),
            "remediation": REMEDIATION_GUIDE.get(vuln_type, {}).get("recommendations", []),
            
            "references": self._get_references(vuln_type)
        }
        
        return poc
    
    def generate_markdown(self, poc: Dict) -> str:
        """Generate markdown POC report."""
        severity_icon = SEVERITY_CVSS.get(poc["severity"], {}).get("color", "⚪")
        
        md = f"""# {poc['title']}

**ID:** {poc['id']}
**Severity:** {severity_icon} {poc['severity'].upper()} (CVSS: {poc['cvss_estimate']})
**Discovered:** {poc['discovered_at']}

---

## Summary

| Field | Value |
|-------|-------|
| Vulnerability Type | {poc['vulnerability_type']} |
| Affected URL | `{poc['affected_url']}` |
| Vulnerable Parameter | `{poc['vulnerable_parameter']}` |
| Payload | `{poc['payload_used']}` |

---

## Steps to Reproduce

{self._format_steps(poc['steps_to_reproduce'])}

---

## Proof of Concept

### cURL Command
```bash
{poc['curl_command']}
```

### Raw HTTP Request
```http
{poc['raw_request']}
```

---

## Evidence

```json
{json.dumps(poc['evidence'], indent=2)}
```

{f"### Response Snippet" if poc['response_snippet'] else ""}
{f"```html{chr(10)}{poc['response_snippet']}{chr(10)}```" if poc['response_snippet'] else ""}

---

## Impact

{poc['impact']}

---

## Remediation

{self._format_remediation(poc['remediation'])}

---

## References

{self._format_references(poc['references'])}
"""
        return md
    
    def save_poc(self, poc: Dict, run_id: str) -> Path:
        """Save POC to file."""
        poc_dir = self.output_dir / f"run_{run_id}" / "pocs"
        poc_dir.mkdir(parents=True, exist_ok=True)
        
        # Save markdown
        md_path = poc_dir / f"{poc['id']}.md"
        md_path.write_text(self.generate_markdown(poc), encoding="utf-8")
        
        # Save JSON
        json_path = poc_dir / f"{poc['id']}.json"
        json_path.write_text(json.dumps(poc, indent=2), encoding="utf-8")
        
        return md_path
    
    def _generate_id(self, finding: Dict) -> str:
        """
        Generate stable POC ID.
        
        Uses VulnKey + SHA256 for deterministic, stable IDs.
        NOT Python hash() which varies across runs.
        """
        # If finding has a pre-computed poc_id (from KB), use it
        if "poc_id" in finding:
            return finding["poc_id"]
        
        # Build VulnKey-style canonical ID
        vuln = finding.get("vuln", "vuln")
        method = finding.get("method", "GET")
        target = finding.get("target", "")
        param = finding.get("param", "unknown")
        location = finding.get("location", "query")
        
        # Create canonical string for hashing
        canonical = f"{method.upper()}:{urllib.parse.urlparse(target).path.lower()}:{param.lower()}:{location.lower()}:{vuln.lower()}"
        short_hash = hashlib.sha256(canonical.encode()).hexdigest()[:12]
        return f"{vuln}_{short_hash}"
    
    def _get_vuln_name(self, vuln_type: str) -> str:
        """Get human-readable vulnerability name."""
        names = {
            "xss": "Cross-Site Scripting (XSS)",
            "sqli": "SQL Injection",
            "idor": "Insecure Direct Object Reference",
            "ssrf": "Server-Side Request Forgery",
            "ssrf_indicator": "Server-Side Request Forgery",
            "file_upload": "Unrestricted File Upload",
            "cors": "CORS Misconfiguration",
            "cmd_injection": "Command Injection",
            "lfi": "Local File Inclusion",
            "rfi": "Remote File Inclusion",
            "xxe": "XML External Entity",
            "csrf": "Cross-Site Request Forgery",
            "auth_bypass": "Authentication Bypass",
            "business_logic": "Business Logic Flaw"
        }
        return names.get(vuln_type, vuln_type.replace("_", " ").title())
    
    def _calculate_severity(self, finding: Dict) -> str:
        """Calculate severity based on vulnerability type and evidence."""
        vuln = finding.get("vuln", "")
        
        critical_vulns = ["sqli", "cmd_injection", "rfi", "file_upload", "auth_bypass"]
        high_vulns = ["xss", "idor", "ssrf", "ssrf_indicator", "lfi", "xxe"]
        medium_vulns = ["cors", "csrf", "open_redirect", "business_logic"]
        
        if vuln in critical_vulns:
            return "critical"
        elif vuln in high_vulns:
            return "high"
        elif vuln in medium_vulns:
            return "medium"
        return "low"
    
    def _extract_endpoint(self, url: str) -> str:
        """Extract endpoint path from URL."""
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.path or "/"
        except Exception as _e:
            return url
    
    def _generate_steps(self, finding: Dict) -> List[str]:
        """Generate step-by-step reproduction instructions."""
        vuln = finding.get("vuln", "")
        target = finding.get("target", "")
        payload = finding.get("payload", "")
        param = finding.get("param", "")
        
        steps = [
            f"Navigate to the target URL: `{target}`"
        ]
        
        if vuln == "xss":
            steps.extend([
                f"Locate the input field or parameter: `{param or 'search/input field'}`",
                f"Enter the following payload: `{payload}`",
                "Submit the form or trigger the request",
                "Observe that the JavaScript executes (alert box, console output, etc.)"
            ])
        elif vuln == "sqli":
            steps.extend([
                f"Identify the injectable parameter: `{param or 'id/search'}`",
                f"Inject the SQL payload: `{payload}`",
                "Observe the response for:",
                "  - SQL error messages (error-based)",
                "  - Different response content (boolean-based)",
                "  - Delayed response (time-based)"
            ])
        elif vuln == "idor":
            steps.extend([
                "Log in as a regular user (User A)",
                f"Access your own resource: `{target}`",
                "Note your user/resource ID",
                "Change the ID parameter to another user's ID",
                "Observe unauthorized access to other user's data"
            ])
        elif vuln in ["ssrf", "ssrf_indicator"]:
            steps.extend([
                f"Locate the URL parameter: `{param or 'url'}`",
                f"Enter an internal URL: `{payload}`",
                "Observe the response for internal service data",
                "Try accessing cloud metadata: `http://169.254.169.254/`"
            ])
        elif vuln == "file_upload":
            steps.extend([
                "Locate the file upload functionality",
                "Prepare a malicious file (e.g., webshell.php)",
                "Upload the file and note the upload path",
                "Access the uploaded file URL",
                "Verify code execution"
            ])
        elif vuln == "cors":
            steps.extend([
                "Make a request with Origin header set to attacker domain",
                f"Request: `curl -H 'Origin: https://evil.com' {target}`",
                "Check if Access-Control-Allow-Origin reflects the evil domain",
                "Verify if credentials are allowed"
            ])
        else:
            steps.extend([
                f"Inject the payload: `{payload}`",
                "Observe the application response",
                "Verify the vulnerability is exploitable"
            ])
        
        return steps
    
    def _generate_curl(self, finding: Dict) -> str:
        """Generate cURL command for reproduction."""
        target = finding.get("target", "")
        payload = finding.get("payload", "")
        param = finding.get("param", "test")
        method = finding.get("method", "GET")
        
        encoded_payload = urllib.parse.quote(str(payload), safe="")
        
        if method.upper() == "GET":
            if "?" in target:
                url = f"{target}&{param}={encoded_payload}"
            else:
                url = f"{target}?{param}={encoded_payload}"
            return f"curl -v '{url}'"
        else:
            return f"curl -v -X POST '{target}' -d '{param}={encoded_payload}'"
    
    def _generate_raw_request(self, finding: Dict) -> str:
        """Generate raw HTTP request."""
        target = finding.get("target", "")
        payload = finding.get("payload", "")
        param = finding.get("param", "test")
        method = finding.get("method", "GET")
        
        try:
            parsed = urllib.parse.urlparse(target)
            host = parsed.netloc
            path = parsed.path or "/"
        except Exception as _e:
            host = "target.com"
            path = "/"
        
        if method.upper() == "GET":
            query = f"{param}={payload}"
            return f"""GET {path}?{query} HTTP/1.1
Host: {host}
User-Agent: AI-Pentester/1.0
Accept: */*
Connection: close"""
        else:
            body = f"{param}={payload}"
            return f"""POST {path} HTTP/1.1
Host: {host}
User-Agent: AI-Pentester/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: {len(body)}
Connection: close

{body}"""
    
    def _extract_response_snippet(self, finding: Dict, max_len: int = 500) -> str:
        """Extract relevant response snippet."""
        evidence = finding.get("evidence", {})
        if isinstance(evidence, dict):
            return evidence.get("response_snippet", "")[:max_len]
        return str(evidence)[:max_len] if evidence else ""
    
    def _describe_impact(self, vuln_type: str) -> str:
        """Describe the potential impact of the vulnerability."""
        impacts = {
            "xss": "An attacker can execute arbitrary JavaScript in the victim's browser, potentially stealing session tokens, performing actions on behalf of the user, or redirecting to malicious sites.",
            "sqli": "An attacker can extract sensitive data from the database, modify or delete data, bypass authentication, or potentially gain command execution on the server.",
            "idor": "An attacker can access or modify resources belonging to other users, leading to data theft, unauthorized actions, or privilege escalation.",
            "ssrf": "An attacker can make the server send requests to internal services, potentially accessing cloud metadata, internal APIs, or pivoting to internal network.",
            "ssrf_indicator": "An attacker can make the server send requests to internal services, potentially accessing cloud metadata, internal APIs, or pivoting to internal network.",
            "file_upload": "An attacker can upload malicious files to the server, potentially achieving remote code execution, defacing the website, or storing malware.",
            "cors": "An attacker can read sensitive data from authenticated endpoints by exploiting misconfigured CORS, potentially stealing user data or tokens.",
            "cmd_injection": "An attacker can execute arbitrary system commands on the server, leading to full server compromise, data theft, or lateral movement.",
            "lfi": "An attacker can read sensitive files from the server, potentially exposing source code, configuration files, or password files."
        }
        return impacts.get(vuln_type, "This vulnerability could allow an attacker to compromise the application security.")
    
    def _get_references(self, vuln_type: str) -> List[Dict]:
        """Get reference links for the vulnerability type."""
        refs = {
            "xss": [
                {"title": "OWASP XSS Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
                {"title": "CWE-79: Improper Neutralization of Input", "url": "https://cwe.mitre.org/data/definitions/79.html"}
            ],
            "sqli": [
                {"title": "OWASP SQL Injection Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
                {"title": "CWE-89: SQL Injection", "url": "https://cwe.mitre.org/data/definitions/89.html"}
            ],
            "idor": [
                {"title": "OWASP IDOR", "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"},
                {"title": "CWE-639: Authorization Bypass", "url": "https://cwe.mitre.org/data/definitions/639.html"}
            ],
            "ssrf": [
                {"title": "OWASP SSRF Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
                {"title": "CWE-918: SSRF", "url": "https://cwe.mitre.org/data/definitions/918.html"}
            ]
        }
        return refs.get(vuln_type, [{"title": "OWASP Top 10", "url": "https://owasp.org/www-project-top-ten/"}])
    
    def _format_steps(self, steps: List[str]) -> str:
        """Format steps as numbered list."""
        return "\n".join([f"{i+1}. {step}" for i, step in enumerate(steps)])
    
    def _format_remediation(self, recommendations: List[str]) -> str:
        """Format remediation as bullet list."""
        return "\n".join([f"- {rec}" for rec in recommendations])
    
    def _format_references(self, refs: List[Dict]) -> str:
        """Format references as links."""
        return "\n".join([f"- [{ref['title']}]({ref['url']})" for ref in refs])


def generate_poc(finding: Dict) -> Dict:
    """Convenience function to generate POC."""
    generator = POCGenerator()
    return generator.generate(finding)
