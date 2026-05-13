"""
Intelligent Payload Selection for AI-Pentester

UPGRADED: Now uses injection point context, vuln_templates preconditions,
and risk-based prioritization for smarter vulnerability testing.
"""

from pathlib import Path
from typing import List, Dict, Optional, Any
import urllib.parse

# Import the intelligent templates
from core.scanner.vuln_templates import (
    VulnerabilityTemplates,
    check_preconditions,
    get_priority_payloads,
    VULNERABILITY_TEMPLATES
)


PAYLOAD_DIR = Path("data/payload_db")

# Fallback payloads if payload_db is empty or missing
FALLBACK_PAYLOADS = {
    "xss": [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '<svg onload=alert(1)>',
    ],
    "sqli": [
        "' OR '1'='1'--",
        "1' AND '1'='1",
        "' UNION SELECT NULL--",
        "1; SELECT SLEEP(2)--",
    ],
    "cmd_injection": [
        "; ls -la",
        "| whoami",
        "$(id)",
        "`cat /etc/passwd`",
    ],
    "lfi": [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
        "..%2F..%2F..%2Fetc%2Fpasswd",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "..\\..\\..\\windows\\win.ini",
    ],
    "ssrf": [
        "http://127.0.0.1:80",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "idor": [
        "probe-idor",
    ],
    "file_upload": [
        "probe-file_upload",
    ],
    "cors": [
        "probe-cors",
    ],
    "open_redirect": [
        "https://evil.example.com",
        "//evil.example.com",
    ],
    "auth_bypass": [
        "probe-auth_bypass",
    ],
    "csrf": [
        "probe-csrf",
    ],
    "brute_force": [
        "probe-brute_force",
    ],
    "information_disclosure": [
        "probe-information_disclosure",
    ],
    "security_headers": [
        "probe-security_headers",
    ],
    "business_logic": [
        "probe-business_logic",
    ],
}


def load_payloads() -> Dict[str, List[str]]:
    """
    Load all payloads from payload database.
    
    Creates the directory if missing and falls back to built-in payloads
    if the directory is empty.
    """
    # Ensure directory exists
    PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)
    
    payloads = {}
    files_found = False
    
    for file in PAYLOAD_DIR.glob("*.txt"):
        files_found = True
        vuln = file.stem
        try:
            lines = [p.strip() for p in file.read_text(encoding='utf-8').splitlines() 
                     if p.strip() and not p.strip().startswith('#')]
            payloads[vuln] = lines
        except Exception as e:
            # Log but don't crash - use fallback for this type
            print(f"[payloads] Warning: Could not load {file}: {e}")
    
    # If no files found or directory empty, use fallback payloads
    if not files_found or not payloads:
        print("[payloads] Warning: payload_db is empty, using built-in fallback payloads")
        return FALLBACK_PAYLOADS.copy()
    
    # Merge fallbacks for any missing types
    for vuln_type, fallback in FALLBACK_PAYLOADS.items():
        if vuln_type not in payloads:
            payloads[vuln_type] = fallback

    # Dataset enrichment: merge extra payloads from SecLists/Nuclei/PAT
    # These are written by core/build_payload_db.py and exist when datasets
    # have been cloned via data/setup_datasets.py.
    # The files in payload_db/ already contain the merged payloads, so this
    # path only fires if someone adds _extra_ files (e.g. _polyglot, _jwt).
    _extra_keys = {
        "_polyglot":       None,   # appended to all vuln types as mutation seeds
        "_jwt_payloads":   "auth_bypass",
        "_oauth_payloads": "auth_bypass",
    }
    _extra_path = PAYLOAD_DIR
    for _src_key, _dst_key in _extra_keys.items():
        _src_file = _extra_path / f"{_src_key}.txt"
        if _src_file.exists():
            try:
                _extra = [p.strip() for p in _src_file.read_text(encoding="utf-8").splitlines()
                          if p.strip() and not p.strip().startswith("#")]
                if _dst_key:
                    payloads.setdefault(_dst_key, [])
                    payloads[_dst_key] = list(dict.fromkeys(payloads[_dst_key] + _extra))
                else:
                    # polyglot — append to every vuln type for edge-case coverage
                    for _vt in list(payloads.keys()):
                        payloads[_vt] = list(dict.fromkeys(payloads[_vt] + _extra[:20]))
            except Exception as _e:
                import logging; logging.getLogger(__name__).debug(f'[payloads] dataset extra merge error: {_e}')

    return payloads



def select_payloads(vuln_type: str, context: Dict) -> List[str]:
    """
    Select payloads for a vulnerability type.
    
    LEGACY function - maintained for backward compatibility.
    For intelligent selection, use select_payloads_for_injection_point().
    """
    payloads = load_payloads()
    selected = payloads.get(vuln_type, [])
    return selected


def select_payloads_for_injection_point(
    vuln_type: str,
    injection_point: Dict,
    max_payloads: int = 20
) -> List[Dict]:
    """
    Intelligent payload selection based on injection point context.
    
    Uses vuln_templates preconditions and context matching to select
    only relevant payloads for the given parameter.
    
    Args:
        vuln_type: Vulnerability type to test (sqli, xss, etc.)
        injection_point: Dict with keys: name, location, context, data_type, risk_score
        max_payloads: Maximum payloads to return (default 20)
    
    Returns:
        List of payload dicts with: original, param, location, context, priority
    """
    templates = VulnerabilityTemplates()
    
    param_name = injection_point.get("name", "")
    data_type = injection_point.get("data_type_guess", "string")
    context = injection_point.get("context", "generic")
    location = injection_point.get("location", "query")
    risk_score = injection_point.get("risk_score", 5)
    reflection = injection_point.get("reflection_behavior", "unknown")
    
    # Check preconditions FIRST - skip if not suitable
    passes, reason = check_preconditions(
        vuln_type=vuln_type,
        param_name=param_name,
        data_type=data_type,
        context=context,
        reflection=reflection
    )
    
    if not passes:
        # Return empty - this vuln type is not suitable for this param
        return []
    
    # Check if parameter name matches vuln type patterns
    if not templates.matches_context(vuln_type, param_name):
        # Parameter doesn't look like a target for this vuln type
        # Reduce payload count significantly
        max_payloads = min(max_payloads, 5)
    
    # Load and prioritize payloads
    raw_payloads = get_priority_payloads(vuln_type, context, max_payloads)
    
    # Adjust count based on risk score (higher risk = more payloads)
    if risk_score >= 7:
        # High risk - use all requested payloads
        pass
    elif risk_score >= 4:
        # Medium risk - use 75%
        raw_payloads = raw_payloads[:int(len(raw_payloads) * 0.75)]
    else:
        # Low risk - use minimal payloads
        raw_payloads = raw_payloads[:5]
    
    # Build payload entries with metadata
    payload_entries = []
    for i, payload in enumerate(raw_payloads):
        payload_entries.append({
            "original": payload,
            "param": param_name,
            "location": location,
            "context": context,
            "priority": len(raw_payloads) - i,  # Higher = earlier
            "vuln_type": vuln_type,
        })
    
    return payload_entries


def get_vuln_types_for_injection_point(injection_point: Dict) -> List[str]:
    """
    Get suitable vulnerability types for an injection point.
    
    Uses parameter name patterns and context to determine which
    vulnerability types are worth testing.
    """
    templates = VulnerabilityTemplates()
    
    param_name = injection_point.get("name", "")
    context = injection_point.get("context", "generic")
    
    return templates.get_suitable_vulns(param_name, context)


def build_intelligent_payload_plan(
    injection_points: List[Dict],
    checklist: Dict,
    max_payloads_per_param: int = 15
) -> Dict[str, List[Dict]]:
    """
    Build an intelligent payload plan using injection points.
    
    This replaces the naive "test all vulns on target" approach with
    targeted testing based on injection point context and risk.
    
    Args:
        injection_points: List of normalized injection points
        checklist: Vulnerability checklist from state  
        max_payloads_per_param: Max payloads per parameter
    
    Returns:
        Dict mapping vuln_type -> list of payload entries
    """
    payload_plan = {}
    
    # Sort injection points by risk score (highest first)
    sorted_points = sorted(
        injection_points,
        key=lambda x: x.get("risk_score", 0),
        reverse=True
    )
    
    for point in sorted_points:
        # Get suitable vuln types for this injection point
        suitable_vulns = get_vuln_types_for_injection_point(point)
        
        for vuln_type in suitable_vulns:
            # Only test if in checklist
            if vuln_type not in checklist:
                continue
            
            # Get intelligent payloads for this param + vuln combo
            payloads = select_payloads_for_injection_point(
                vuln_type=vuln_type,
                injection_point=point,
                max_payloads=max_payloads_per_param
            )
            
            if payloads:
                if vuln_type not in payload_plan:
                    payload_plan[vuln_type] = []
                payload_plan[vuln_type].extend(payloads)
    
    return payload_plan


def mutate_payload(payload) -> Dict:
    """
    Apply standard mutations to a payload.
    
    Handles both string payloads (legacy) and dict payloads (new).
    """
    if isinstance(payload, dict):
        original = payload.get("original", "")
        result = {
            **payload,
            "url_encoded": urllib.parse.quote(original),
            "double_encoded": urllib.parse.quote(urllib.parse.quote(original))
        }
    else:
        result = {
            "original": payload,
            "url_encoded": urllib.parse.quote(str(payload)),
            "double_encoded": urllib.parse.quote(urllib.parse.quote(str(payload)))
        }
    return result
