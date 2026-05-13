"""
Dynamic Checklist Generator for AI-Pentester
Generates vulnerability checklist based on reconnaissance results.
"""

from typing import List, Dict, Set

# Vulnerability categories with their triggers
VULN_TRIGGERS = {
    # Technology-based triggers
    "technologies": {
        "php": ["sqli", "lfi", "rfi", "file_upload", "php_deserialization", "cmd_injection", "path_traversal", "xxe", "ssti"],
        "asp": ["sqli", "file_upload", "asp_injection"],
        "aspx": ["sqli", "file_upload", "viewstate_tampering"],
        "java": ["sqli", "xxe", "java_deserialization", "log4j"],
        "node": ["prototype_pollution", "ssrf", "nosql_injection"],
        "python": ["ssti", "ssrf", "pickle_deserialization"],
        "wordpress": ["sqli", "xss", "file_upload", "plugin_vulns"],
        "drupal": ["sqli", "xss", "drupalgeddon"],
        "joomla": ["sqli", "xss", "file_upload"],
    },
    
    # Header-based triggers
    "headers": {
        "x-powered-by": ["tech_disclosure"],
        "server": ["tech_disclosure"],
        "x-aspnet-version": ["tech_disclosure", "viewstate_tampering"],
    },
    
    # Form-based triggers
    "forms": {
        "login": ["sqli", "brute_force", "credential_stuffing", "auth_bypass"],
        "search": ["xss", "sqli", "ldap_injection"],
        "upload": ["file_upload", "path_traversal"],
        "contact": ["xss", "email_injection", "spam"],
        "register": ["sqli", "mass_assignment", "privilege_escalation"],
        "password": ["password_reset_poisoning", "token_leakage"],
    },
    
    # Parameter-based triggers
    "parameters": {
        "id": ["idor", "sqli"],
        "user_id": ["idor", "sqli"],
        "file": ["lfi", "path_traversal", "rfi"],
        "path": ["path_traversal", "lfi"],
        "url": ["ssrf", "open_redirect"],
        "redirect": ["open_redirect"],
        "callback": ["ssrf", "xss"],
        "page": ["lfi", "sqli"],
        "sort": ["sqli"],
        "order": ["sqli"],
        "q": ["xss", "sqli"],
        "search": ["xss", "sqli"],
        "email": ["sqli", "email_injection"],
        "xml": ["xxe"],
        "data": ["xxe", "deserialization"],
    }
}

# Default vulnerabilities to always check on every target
DEFAULT_VULNS = [
    # Critical & High - always test
    "xss",
    "sqli",
    "idor",
    "ssrf",
    "file_upload",
    "lfi",
    "path_traversal",
    "cmd_injection",
    "auth_bypass",
    "business_logic",
    # Medium - always test
    "cors",
    "open_redirect",
    "csrf",
    "brute_force",
    "information_disclosure",
    # Low - always test
    "security_headers",
]

# Vulnerability metadata
VULN_INFO = {
    "xss": {"name": "Cross-Site Scripting", "severity": "high", "category": "injection"},
    "sqli": {"name": "SQL Injection", "severity": "critical", "category": "injection"},
    "idor": {"name": "Insecure Direct Object Reference", "severity": "high", "category": "access_control"},
    "ssrf": {"name": "Server-Side Request Forgery", "severity": "high", "category": "ssrf"},
    "lfi": {"name": "Local File Inclusion", "severity": "high", "category": "file"},
    "rfi": {"name": "Remote File Inclusion", "severity": "critical", "category": "file"},
    "file_upload": {"name": "Unrestricted File Upload", "severity": "critical", "category": "file"},
    "path_traversal": {"name": "Path Traversal", "severity": "high", "category": "file"},
    "xxe": {"name": "XML External Entity", "severity": "high", "category": "injection"},
    "cors": {"name": "CORS Misconfiguration", "severity": "medium", "category": "config"},
    "open_redirect": {"name": "Open Redirect", "severity": "medium", "category": "redirect"},
    "csrf": {"name": "Cross-Site Request Forgery", "severity": "medium", "category": "csrf"},
    "auth_bypass": {"name": "Authentication Bypass", "severity": "critical", "category": "auth"},
    "brute_force": {"name": "Brute Force", "severity": "medium", "category": "auth"},
    "ssti": {"name": "Server-Side Template Injection", "severity": "critical", "category": "injection"},
    "cmd_injection": {"name": "Command Injection", "severity": "critical", "category": "injection"},
    "nosql_injection": {"name": "NoSQL Injection", "severity": "high", "category": "injection"},
    "ldap_injection": {"name": "LDAP Injection", "severity": "high", "category": "injection"},
    "security_headers": {"name": "Missing Security Headers", "severity": "low", "category": "config"},
    "information_disclosure": {"name": "Information Disclosure", "severity": "medium", "category": "info"},
    "business_logic": {"name": "Business Logic Flaw", "severity": "high", "category": "logic"},
}


class ChecklistGenerator:
    """
    Generate dynamic vulnerability checklist based on reconnaissance.
    """
    
    def __init__(self):
        self.triggers = VULN_TRIGGERS
        self.vuln_info = VULN_INFO
    
    def generate(self, recon_profile) -> List[Dict]:
        """
        Generate checklist from recon profile.
        
        Returns list of checklist items:
        [
            {
                "vuln": "xss",
                "name": "Cross-Site Scripting",
                "severity": "high",
                "reason": "Forms detected with search functionality",
                "priority": 1,
                "status": "pending"
            }
        ]
        """
        detected_vulns: Dict[str, Set[str]] = {}  # vuln -> set of reasons
        
        # Add default vulnerabilities
        for vuln in DEFAULT_VULNS:
            detected_vulns.setdefault(vuln, set()).add("Default check")
        
        # Check technologies
        technologies = self._get_field(recon_profile, "technologies", [])
        for tech in technologies:
            tech_lower = tech.lower()
            for trigger_tech, vulns in self.triggers["technologies"].items():
                if trigger_tech in tech_lower:
                    for vuln in vulns:
                        detected_vulns.setdefault(vuln, set()).add(f"Technology: {tech}")
        
        # Check forms
        forms = self._get_field(recon_profile, "forms", [])
        for form in forms:
            action = str(form.get("action", "")).lower()
            inputs = form.get("inputs", [])
            
            for trigger_form, vulns in self.triggers["forms"].items():
                if trigger_form in action:
                    for vuln in vulns:
                        detected_vulns.setdefault(vuln, set()).add(f"Form: {trigger_form}")
            
            # Check form inputs
            for inp in inputs:
                inp_name = str(inp).lower() if isinstance(inp, str) else str(inp.get("name", "")).lower()
                for trigger_param, vulns in self.triggers["parameters"].items():
                    if trigger_param in inp_name:
                        for vuln in vulns:
                            detected_vulns.setdefault(vuln, set()).add(f"Parameter: {inp_name}")
        
        # Check parameters
        parameters = self._get_field(recon_profile, "parameters", [])
        for param in parameters:
            param_lower = param.lower() if isinstance(param, str) else ""
            for trigger_param, vulns in self.triggers["parameters"].items():
                if trigger_param in param_lower:
                    for vuln in vulns:
                        detected_vulns.setdefault(vuln, set()).add(f"Parameter: {param}")
        
        # Check endpoints for patterns
        endpoints = self._get_field(recon_profile, "endpoints", [])
        for endpoint in endpoints:
            endpoint_lower = str(endpoint).lower()
            
            # File-based patterns
            if any(ext in endpoint_lower for ext in [".php", ".asp", ".jsp"]):
                detected_vulns.setdefault("lfi", set()).add(f"Endpoint pattern")
                detected_vulns.setdefault("sqli", set()).add(f"Endpoint pattern")
            
            # Admin patterns
            if "admin" in endpoint_lower:
                detected_vulns.setdefault("auth_bypass", set()).add("Admin path detected")
                detected_vulns.setdefault("brute_force", set()).add("Admin path detected")
            
            # API patterns
            if "/api/" in endpoint_lower:
                detected_vulns.setdefault("idor", set()).add("API endpoint detected")
                detected_vulns.setdefault("business_logic", set()).add("API endpoint detected")
        
        # Build checklist with priorities
        checklist = []
        for vuln, reasons in detected_vulns.items():
            info = self.vuln_info.get(vuln, {"name": vuln.title(), "severity": "medium", "category": "unknown"})
            
            priority = self._calculate_priority(info["severity"], len(reasons))
            
            checklist.append({
                "vuln": vuln,
                "name": info["name"],
                "severity": info["severity"],
                "category": info["category"],
                "reasons": list(reasons),
                "priority": priority,
                "status": "pending"
            })
        
        # Sort by priority (lower = higher priority)
        checklist.sort(key=lambda x: x["priority"])
        
        return checklist
    
    def _get_field(self, profile, field, default):
        """Safely get field from profile (dict or object)."""
        if hasattr(profile, field):
            return getattr(profile, field)
        if isinstance(profile, dict):
            return profile.get(field, default)
        return default
    
    def _calculate_priority(self, severity: str, reason_count: int) -> int:
        """Calculate priority score (lower = higher priority)."""
        severity_scores = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4
        }
        base = severity_scores.get(severity, 3)
        # More evidence = higher priority
        evidence_bonus = min(reason_count - 1, 2) * 0.1
        return round((base - evidence_bonus) * 10)
    
    def format_checklist(self, checklist: List[Dict]) -> str:
        """Format checklist as markdown."""
        lines = ["# Vulnerability Checklist\n"]
        
        current_severity = None
        for item in checklist:
            if item["severity"] != current_severity:
                current_severity = item["severity"]
                lines.append(f"\n## {current_severity.upper()} Severity\n")
            
            status_icon = "☐" if item["status"] == "pending" else "☑" if item["status"] == "found" else "☒"
            lines.append(f"- {status_icon} **{item['name']}** (`{item['vuln']}`)")
            lines.append(f"  - Reasons: {', '.join(item['reasons'][:3])}")
        
        return "\n".join(lines)


def generate_checklist(recon_profile) -> List[Dict]:
    """Convenience function to generate checklist."""
    generator = ChecklistGenerator()
    return generator.generate(recon_profile)
