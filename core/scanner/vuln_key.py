"""
Canonical Vulnerability Key - Core Data Model

This module defines the canonical vulnerability identification system.
One vulnerability = One (method + endpoint + parameter + location + vuln_type)

RULES:
- VulnKey is frozen (immutable, hashable, thread-safe)
- All normalization goes through normalize_vuln_key() - NO AD-HOC CREATION
- Evidence scores determine which payload is kept for POC
- ScanMode controls discovery vs exploitation behavior
"""

import re
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from urllib.parse import urlparse, unquote


# =============================================================================
# SCAN MODES
# =============================================================================

class ScanMode(Enum):
    """Controls scanner behavior for different phases."""
    DISCOVERY = "discovery"        # Find new vulnerabilities
    EXPLOITATION = "exploitation"  # Exploit known vulnerabilities
    CHAINING = "chaining"          # Chain confirmed vulnerabilities


# =============================================================================
# CANONICAL VULNERABILITY KEY
# =============================================================================

@dataclass(frozen=True)
class VulnKey:
    """
    Canonical vulnerability identifier.
    
    Golden Rule: One vulnerability = One VulnKey
    
    This is frozen (immutable) for:
    - Thread safety
    - Hashability (can be dict/set key)
    - Preventing accidental modification
    """
    method: str                    # GET, POST, PUT, DELETE, PATCH
    endpoint: str                  # Normalized path (no query string)
    parameter: str                 # Parameter name (normalized)
    parameter_location: str        # query | body | json | header | cookie
    vuln_type: str                 # sqli, xss, ssrf, etc.
    
    def __str__(self) -> str:
        return f"{self.method}:{self.endpoint}:{self.parameter}[{self.parameter_location}]:{self.vuln_type}"
    
    def to_dict(self) -> Dict[str, str]:
        return {
            "method": self.method,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "parameter_location": self.parameter_location,
            "vuln_type": self.vuln_type,
        }


# =============================================================================
# EVIDENCE MODEL
# =============================================================================

@dataclass
class Evidence:
    """
    Evidence for a confirmed vulnerability.
    
    Scores determine which evidence is kept:
    - Higher score = stronger evidence
    - When new evidence arrives, keep the one with higher score
    """
    payload: str
    response_snippet: str
    score: int                     # Higher = stronger (1-100)
    confidence: str                # low | medium | high
    request_details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "payload": self.payload,
            "response_snippet": self.response_snippet,
            "score": self.score,
            "confidence": self.confidence,
            "request_details": self.request_details,
        }


# =============================================================================
# NORMALIZATION FUNCTIONS
# =============================================================================

def normalize_endpoint(url: str) -> str:
    """
    Normalize URL endpoint for canonical comparison.
    
    Rules:
    - Remove query string
    - URL decode path
    - Collapse multiple slashes
    - Remove trailing slash
    - Lowercase
    
    Examples:
        /API/User -> /api/user
        /api//users/ -> /api/users
        %2Fapi%2Fusers -> /api/users
    """
    parsed = urlparse(url)
    path = unquote(parsed.path)
    path = re.sub(r"/{2,}", "/", path)  # Collapse //
    path = path.rstrip("/")
    return path.lower() if path else "/"


def normalize_param(param: str) -> str:
    """
    Normalize parameter name.
    
    Rules:
    - Lowercase
    - Remove array brackets
    
    Examples:
        id[] -> id
        ID -> id
        user[name] -> user[name -> user[name (preserves nested)
    """
    param = param.lower()
    param = param.rstrip("[]")
    return param


def normalize_location(location: str) -> str:
    """
    Normalize parameter location.
    
    Valid locations: query, body, json, header, cookie
    """
    location = location.lower().strip()
    
    # Map common aliases
    aliases = {
        "querystring": "query",
        "qs": "query",
        "post": "body",
        "form": "body",
        "json-body": "json",
        "jsonbody": "json",
        "headers": "header",
        "cookies": "cookie",
    }
    
    return aliases.get(location, location)


def normalize_vuln_key(
    method: str,
    url: str,
    param: str,
    param_location: str,
    vuln_type: str
) -> VulnKey:
    """
    Create a normalized VulnKey.
    
    THIS IS THE ONLY WAY TO CREATE A VULNKEY.
    Do NOT create VulnKey directly - always use this function.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full URL or path
        param: Parameter name
        param_location: Where param is (query, body, json, header, cookie)
        vuln_type: Vulnerability type (sqli, xss, etc.)
    
    Returns:
        Normalized, canonical VulnKey
    """
    return VulnKey(
        method=method.upper().strip(),
        endpoint=normalize_endpoint(url),
        parameter=normalize_param(param),
        parameter_location=normalize_location(param_location),
        vuln_type=vuln_type.lower().strip(),
    )


# =============================================================================
# POC ID GENERATION
# =============================================================================

def generate_poc_id(vuln_key: VulnKey) -> str:
    """
    Generate stable, deterministic POC ID from VulnKey.
    
    Uses SHA256 hash (NOT Python hash() which is non-deterministic).
    Returns 12-character hex string.
    
    This ensures:
    - Same vuln always gets same POC ID
    - POC IDs are stable across runs
    - No collisions in practice
    """
    raw = f"{vuln_key.method}:{vuln_key.endpoint}:{vuln_key.parameter}:{vuln_key.parameter_location}:{vuln_key.vuln_type}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


# =============================================================================
# EVIDENCE SCORING
# =============================================================================

def calculate_evidence_score(
    vuln_type: str,
    response_code: int,
    response_body: str,
    payload: str
) -> int:
    """
    Calculate evidence score based on confirmation strength.
    
    Higher score = stronger evidence.
    
    Score ranges:
    - 1-30: Weak (reflection only)
    - 31-60: Medium (pattern match)
    - 61-90: Strong (execution indicators)
    - 91-100: Critical (clear confirmation)
    """
    score = 10  # Base score
    
    # Response code scoring
    if response_code == 200:
        score += 10
    elif response_code in [500, 502, 503]:
        # Server error can indicate injection success
        score += 15
    
    # Vuln-specific scoring
    if vuln_type == "sqli":
        if any(x in response_body.lower() for x in ["sql", "mysql", "postgresql", "oracle", "syntax error"]):
            score += 40
        if "error" in response_body.lower() and any(x in response_body.lower() for x in ["query", "select", "insert"]):
            score += 30
    
    elif vuln_type == "xss":
        if payload in response_body:
            score += 30  # Reflected
        if "<script" in response_body.lower() and "alert" in response_body.lower():
            score += 50
    
    elif vuln_type == "cmd_injection":
        if any(x in response_body for x in ["root:", "uid=", "Windows IP"]):
            score += 60
    
    elif vuln_type == "lfi":
        if "root:" in response_body or "[boot loader]" in response_body:
            score += 60
    
    elif vuln_type == "ssrf":
        if any(x in response_body for x in ["127.0.0.1", "localhost", "169.254.169.254"]):
            score += 40
    
    return min(score, 100)


def determine_confidence(score: int) -> str:
    """Map evidence score to confidence level."""
    if score >= 70:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"
