"""
Vulnerability Templates - Precondition-based vulnerability testing

This module implements vulnerability templates with:
- Preconditions required before testing
- Payload selection logic
- Response analysis patterns

Templates ensure intelligent scanning - only testing vulnerabilities
that make sense for the given injection point context.
"""

from typing import Dict, List, Optional, Tuple, Callable
from pathlib import Path
from dataclasses import dataclass
from enum import Enum


class VulnType(Enum):
    """Supported vulnerability types."""
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    CMD_INJECTION = "cmd_injection"
    SSRF = "ssrf"
    LFI = "lfi"
    PATH_TRAVERSAL = "path_traversal"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    CORS = "cors"


# Preconditions required for each vulnerability type
VULNERABILITY_PRECONDITIONS: Dict[str, List[str]] = {
    "sqli": [
        "string_or_numeric_parameter",
    ],
    "xss": [
        "html_or_js_context",
    ],
    "ssti": [
        "template_context",
    ],
    "cmd_injection": [
        "os_context",
    ],
    "ssrf": [
        "url_like_input",
    ],
    "lfi": [
        "path_like_input",
    ],
    "path_traversal": [
        "path_like_input",
    ],
    "idor": [
        "numeric_identifier",
    ],
    "open_redirect": [
        "url_like_input",
    ],
}


@dataclass
class VulnTemplate:
    """Template for vulnerability testing."""
    vuln_type: str
    preconditions: List[str]
    payload_file: str
    context_patterns: List[str]  # Parameter name patterns
    response_indicators: List[str]  # Response patterns indicating success
    severity: str  # critical, high, medium, low


# Vulnerability templates with full configuration
VULNERABILITY_TEMPLATES: Dict[str, VulnTemplate] = {
    "sqli": VulnTemplate(
        vuln_type="sqli",
        preconditions=["string_or_numeric_parameter"],
        payload_file="sqli.txt",
        context_patterns=[r"id$", r"_id$", r"user", r"name", r"email", r"search", r"query"],
        response_indicators=[
            r"SQL syntax.*?MySQL",
            r"PostgreSQL.*?ERROR",
            r"ORA-\d+",
            r"SQLite",
            r"ODBC.*?Driver",
        ],
        severity="critical"
    ),
    "xss": VulnTemplate(
        vuln_type="xss",
        preconditions=["html_or_js_context"],
        payload_file="xss.txt",
        context_patterns=[r"name", r"message", r"comment", r"title", r"content", r"search"],
        response_indicators=[
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<img[^>]+onerror",
        ],
        severity="high"
    ),
    "ssti": VulnTemplate(
        vuln_type="ssti",
        preconditions=["template_context"],
        payload_file="ssti.txt",
        context_patterns=[r"template", r"render", r"page", r"view", r"layout"],
        # FIX VT1: "49" alone was a false-positive magnet (prices, IDs, line numbers
        # all contain "49"). Use word-boundary regex that requires the number to stand
        # alone in the response, not be embedded in other digits.
        # NOTE: These indicators are used by scan_scheduler for precondition checks.
        # The actual SSTI *detection* in executor.py uses SSTI_EVAL_MAP with a
        # dedicated handler that checks for evaluated output, not reflected input.
        response_indicators=[
            r"\b49\b",        # 7*7 evaluated by Jinja2/Twig/FreeMarker
            r"\b823543\b",    # 7**7 evaluated by Jinja2 (exponentiation probe)
            r"TemplateSyntaxError",
            r"jinja2\.exceptions",
            r"FreeMarker template error",
            r"Twig_Error",
            r"Traceback \(most recent call last\)",
        ],
        severity="critical"
    ),
    "cmd_injection": VulnTemplate(
        vuln_type="cmd_injection",
        preconditions=["os_context"],
        payload_file="cmd_injection.txt",
        context_patterns=[r"cmd", r"exec", r"run", r"ping", r"host", r"command", r"ip"],
        response_indicators=[
            r"root:",  # /etc/passwd
            r"uid=\d+",  # id command
            r"Windows IP",  # ipconfig
            r"bytes from",  # ping response
        ],
        severity="critical"
    ),
    "ssrf": VulnTemplate(
        vuln_type="ssrf",
        preconditions=["url_like_input"],
        payload_file="ssrf.txt",
        context_patterns=[r"url", r"link", r"callback", r"webhook", r"fetch", r"proxy"],
        response_indicators=[
            r"localhost",
            r"127\.0\.0\.1",
            r"169\.254\.169\.254",
            r"internal",
        ],
        severity="high"
    ),
    "lfi": VulnTemplate(
        vuln_type="lfi",
        preconditions=["path_like_input"],
        payload_file="lfi.txt",
        context_patterns=[r"file", r"path", r"include", r"template", r"page", r"document"],
        response_indicators=[
            r"root:.*:0:0:",  # /etc/passwd
            r"\[boot loader\]",  # Windows boot.ini
            r"<?php",  # PHP source
        ],
        severity="high"
    ),
    "path_traversal": VulnTemplate(
        vuln_type="path_traversal",
        preconditions=["path_like_input"],
        payload_file="path_traversal.txt",
        context_patterns=[r"file", r"path", r"dir", r"folder", r"download"],
        response_indicators=[
            r"root:.*:0:0:",
            r"\[fonts\]",  # Windows
        ],
        severity="high"
    ),
    "open_redirect": VulnTemplate(
        vuln_type="open_redirect",
        preconditions=["url_like_input"],
        payload_file="open_redirect.txt",
        context_patterns=[r"redirect", r"next", r"return", r"url", r"goto", r"continue"],
        response_indicators=[],  # Checked via redirect behavior
        severity="medium"
    ),
}


class VulnerabilityTemplates:
    """
    Manages vulnerability templates and payload loading.
    """
    
    PAYLOAD_DIR = Path("data/payload_db")
    
    def __init__(self):
        self.templates = VULNERABILITY_TEMPLATES
        self._payload_cache: Dict[str, List[str]] = {}
    
    def get_template(self, vuln_type: str) -> Optional[VulnTemplate]:
        """Get template for a vulnerability type."""
        return self.templates.get(vuln_type)
    
    def get_preconditions(self, vuln_type: str) -> List[str]:
        """Get preconditions for a vulnerability type."""
        return VULNERABILITY_PRECONDITIONS.get(vuln_type, [])
    
    def load_payloads(self, vuln_type: str) -> List[str]:
        """
        Load payloads for a vulnerability type.
        
        Returns list of payload strings from the payload file.
        """
        if vuln_type in self._payload_cache:
            return self._payload_cache[vuln_type]
        
        template = self.templates.get(vuln_type)
        if not template:
            return []
        
        payload_file = self.PAYLOAD_DIR / template.payload_file
        
        if not payload_file.exists():
            return []
        
        try:
            payloads = []
            for line in payload_file.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.append(line)
            
            self._payload_cache[vuln_type] = payloads
            return payloads
        except Exception as _e:
            return []
    
    def get_context_patterns(self, vuln_type: str) -> List[str]:
        """Get parameter name patterns for a vuln type."""
        template = self.templates.get(vuln_type)
        return template.context_patterns if template else []
    
    def get_response_indicators(self, vuln_type: str) -> List[str]:
        """Get response patterns that indicate vulnerability."""
        template = self.templates.get(vuln_type)
        return template.response_indicators if template else []
    
    def matches_context(self, vuln_type: str, param_name: str) -> bool:
        """
        Check if a parameter name matches the vuln type context.
        
        Used for intelligent payload selection.
        """
        import re
        
        patterns = self.get_context_patterns(vuln_type)
        if not patterns:
            return True  # No patterns = accept all
        
        param_lower = param_name.lower()
        for pattern in patterns:
            if re.search(pattern, param_lower):
                return True
        
        return False
    
    def get_suitable_vulns(self, param_name: str, context: str = "generic") -> List[str]:
        """
        Get vulnerability types suitable for a parameter.
        
        Args:
            param_name: Parameter name
            context: Context (sql, html, js, os, path, etc.)
        
        Returns:
            List of suitable vulnerability type names
        """
        suitable = []
        
        for vuln_type, template in self.templates.items():
            # Check if parameter matches context patterns
            if self.matches_context(vuln_type, param_name):
                suitable.append(vuln_type)
                continue
            
            # Check if context matches preconditions
            preconditions = template.preconditions
            
            if context == "sql" and "string_or_numeric_parameter" in preconditions:
                suitable.append(vuln_type)
            elif context in ["html", "js"] and "html_or_js_context" in preconditions:
                suitable.append(vuln_type)
            elif context == "os" and "os_context" in preconditions:
                suitable.append(vuln_type)
            elif context == "path" and "path_like_input" in preconditions:
                suitable.append(vuln_type)
            elif context == "url" and "url_like_input" in preconditions:
                suitable.append(vuln_type)
        
        return list(set(suitable))


def check_preconditions(
    vuln_type: str,
    param_name: str,
    data_type: str,
    context: str,
    reflection: str = "unknown"
) -> Tuple[bool, str]:
    """
    Check if preconditions are met for testing a vulnerability.
    
    Args:
        vuln_type: Vulnerability type to test
        param_name: Parameter name
        data_type: Parameter data type (string, number, etc.)
        context: Context (html, js, sql, etc.)
        reflection: Reflection behavior (reflected, not_reflected, unknown)
    
    Returns:
        Tuple of (passes: bool, reason: str)
    """
    preconditions = VULNERABILITY_PRECONDITIONS.get(vuln_type, [])
    
    for precond in preconditions:
        if precond == "string_or_numeric_parameter":
            if data_type not in ["string", "number"]:
                return False, f"Data type {data_type} not suitable for {vuln_type}"
        
        elif precond == "html_or_js_context":
            if context not in ["html", "js", "generic"]:
                return False, f"Context {context} not suitable for XSS"
            if reflection == "not_reflected":
                return False, "Parameter not reflected in response"
        
        elif precond == "template_context":
            if not any(x in param_name.lower() for x in ["template", "render", "page"]):
                if context != "generic":
                    return False, "Parameter doesn't appear template-related"
        
        elif precond == "os_context":
            if context != "os":
                if not any(x in param_name.lower() for x in ["cmd", "exec", "ping", "host"]):
                    return False, "Parameter doesn't appear OS-related"
        
        elif precond == "url_like_input":
            if data_type != "url":
                if not any(x in param_name.lower() for x in ["url", "link", "callback", "redirect"]):
                    return False, "Parameter doesn't appear URL-like"
        
        elif precond == "path_like_input":
            if context != "path":
                if not any(x in param_name.lower() for x in ["file", "path", "dir", "include"]):
                    return False, "Parameter doesn't appear path-like"
        
        elif precond == "numeric_identifier":
            if data_type != "number":
                if not any(x in param_name.lower() for x in ["id", "uid", "num"]):
                    return False, "Parameter doesn't appear to be numeric ID"
    
    return True, ""


def get_priority_payloads(
    vuln_type: str,
    param_context: str = "generic",
    max_payloads: int = 10
) -> List[str]:
    """
    Get prioritized payloads for a vulnerability type.
    
    Returns a subset of payloads most likely to succeed based on context.
    """
    templates = VulnerabilityTemplates()
    all_payloads = templates.load_payloads(vuln_type)
    
    if not all_payloads:
        return []
    
    # For now, return first N payloads
    # In production, would implement intelligent selection
    return all_payloads[:max_payloads]
