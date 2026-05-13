"""
Attack Chaining Module with Confidence Scoring

Analyzes confirmed findings and suggests high-impact attack chains
with likelihood, impact, and manual effort estimates.

ENHANCED: Now includes more chain patterns and integrates with
knowledge base for richer chain suggestions.
"""

from pathlib import Path
from typing import List, Dict, Optional, Tuple

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# Chain patterns with impact and confidence ratings
CHAIN_PATTERNS = {
    "idor_file_upload": {
        "requires": ["idor", "file_upload"],
        "chain_name": "IDOR + File Upload",
        "impact": "critical",
        "impact_score": 9,
        "likelihood": 0.7,
        "manual_effort": "medium",
        "description": "Upload malicious file under another user's context for RCE/privilege escalation",
        "exploitation_steps": [
            "1. Use IDOR to access victim's upload endpoint",
            "2. Upload webshell or malicious file",
            "3. Execute uploaded file for RCE"
        ]
    },
    "xss_cors": {
        "requires": ["xss", "cors"],
        "chain_name": "XSS + CORS Misconfiguration",
        "impact": "high",
        "impact_score": 8,
        "likelihood": 0.8,
        "manual_effort": "low",
        "description": "Exfiltrate tokens/data via XSS using relaxed CORS",
        "exploitation_steps": [
            "1. Inject XSS payload to execute in victim's browser",
            "2. Use CORS misconfiguration to send credentials cross-origin",
            "3. Capture session tokens or sensitive data"
        ]
    },
    "open_redirect_xss": {
        "requires": ["open_redirect", "xss"],
        "chain_name": "Open Redirect + XSS",
        "impact": "high",
        "impact_score": 7,
        "likelihood": 0.6,
        "manual_effort": "medium",
        "description": "Phishing via trusted redirect to XSS payload",
        "exploitation_steps": [
            "1. Craft URL with open redirect to attacker-controlled page",
            "2. Deliver XSS payload via redirect destination",
            "3. Capture credentials or session data"
        ]
    },
    "sqli_lfi": {
        "requires": ["sqli", "lfi"],
        "chain_name": "SQLi + LFI",
        "impact": "critical",
        "impact_score": 10,
        "likelihood": 0.5,
        "manual_effort": "high",
        "description": "Use SQLi to write files, then LFI to execute",
        "exploitation_steps": [
            "1. Use SQLi to write PHP shell via INTO OUTFILE",
            "2. Use LFI to include and execute the shell",
            "3. Gain RCE on the server"
        ]
    },
    "ssrf_idor": {
        "requires": ["ssrf", "idor"],
        "chain_name": "SSRF + IDOR",
        "impact": "critical",
        "impact_score": 9,
        "likelihood": 0.6,
        "manual_effort": "medium",
        "description": "Access internal services for other users' data",
        "exploitation_steps": [
            "1. Use SSRF to access internal APIs",
            "2. Combine with IDOR to access other users' resources",
            "3. Exfiltrate sensitive data from internal services"
        ]
    },
    "xss_sqli": {
        "requires": ["xss", "sqli"],
        "chain_name": "XSS + SQLi",
        "impact": "critical",
        "impact_score": 9,
        "likelihood": 0.4,
        "manual_effort": "high",
        "description": "XSS to capture admin credentials, SQLi for data access",
        "exploitation_steps": [
            "1. Use XSS to steal admin session/credentials",
            "2. Access admin panel with stolen credentials",
            "3. Use SQLi in admin context for database access"
        ]
    },
    "cmd_injection_lfi": {
        "requires": ["cmd_injection", "lfi"],
        "chain_name": "Command Injection + LFI",
        "impact": "critical",
        "impact_score": 10,
        "likelihood": 0.7,
        "manual_effort": "low",
        "description": "Full server compromise via multiple vectors",
        "exploitation_steps": [
            "1. Use command injection for initial access",
            "2. Read sensitive files via LFI for credentials",
            "3. Pivot to other services using discovered credentials"
        ]
    },
    "path_traversal_file_upload": {
        "requires": ["path_traversal", "file_upload"],
        "chain_name": "Path Traversal + File Upload",
        "impact": "critical",
        "impact_score": 9,
        "likelihood": 0.7,
        "manual_effort": "medium",
        "description": "Upload files to arbitrary locations",
        "exploitation_steps": [
            "1. Craft upload with path traversal in filename",
            "2. Upload webshell to web-accessible directory",
            "3. Execute shell for RCE"
        ]
    },
}


def _load_yaml_chains() -> dict:
    """B-07 FIX: Load attack chains from config/chain_patterns.yaml.
    YAML chain entries are converted from list format to the keyed dict format
    used by CHAIN_PATTERNS and merged in (YAML wins on duplicate keys).
    """
    if not _YAML_AVAILABLE:
        return {}

    config_path = Path(__file__).resolve().parent.parent / "config" / "chain_patterns.yaml"
    if not config_path.exists():
        return {}

    try:
        with open(config_path, "r") as f:
            data = _yaml.safe_load(f)

        yaml_chains = {}
        for chain in data.get("chains", []):
            name = chain.get("name", "")
            if not name:
                continue
            # Build a dict key from the chain name (lowercase, spaces → _)
            key = name.lower().replace(" ", "_").replace("+", "_")
            steps = chain.get("steps", [])
            requires = [step.get("vuln", "") for step in steps if step.get("vuln")]
            # Map YAML severity to numeric impact_score
            severity_score = {"critical": 9, "high": 7, "medium": 5, "low": 3}
            severity = chain.get("severity", "medium")
            exploitation_steps = [
                f"{i+1}. {step.get('action', '')}" for i, step in enumerate(steps)
            ]
            yaml_chains[key] = {
                "requires": requires,
                "chain_name": name,
                "impact": severity,
                "impact_score": severity_score.get(severity, 5),
                "likelihood": 0.6,         # Sensible default
                "manual_effort": "medium",  # Sensible default
                "description": chain.get("impact", ""),
                "exploitation_steps": exploitation_steps,
            }
        return yaml_chains
    except Exception as e:
        print(f"[Chaining] Warning: could not load chain_patterns.yaml: {e}")
        return {}


# B-07 FIX: Merge YAML chains into CHAIN_PATTERNS (YAML overrides hardcoded on collision)
CHAIN_PATTERNS.update(_load_yaml_chains())


def suggest_chains(state: Dict, logger) -> List[Dict]:
    """
    Analyze findings and suggest high-impact chains with confidence scoring.
    
    Returns a list of suggested chains with:
    - chain_name: Human-readable chain name
    - impact: Impact severity (critical/high/medium/low)
    - impact_score: Numeric impact (1-10)
    - likelihood: Probability of exploitation success (0.0-1.0)
    - manual_effort: Effort required (low/medium/high)
    - exploitation_steps: Step-by-step exploitation guide
    - evidence: Supporting findings
    """
    suggestions = []
    checklist = state.get("checklist", {})
    layer4 = state.get("layer_4", {})

    def found(v): 
        return checklist.get(v) == "FOUND"
    
    def get_evidence(v):
        return layer4.get(v, [])

    # Check all chain patterns
    for pattern_id, pattern in CHAIN_PATTERNS.items():
        required_vulns = pattern["requires"]
        
        # Check if all required vulns are found
        if all(found(v) for v in required_vulns):
            # Calculate chain confidence
            # Base confidence from likelihood, adjusted by number of findings
            evidence = {f"{v}_results": get_evidence(v) for v in required_vulns}
            
            # Count evidence items
            evidence_count = sum(
                len(e) if isinstance(e, list) else 1 
                for e in evidence.values()
            )
            
            # Adjust confidence based on evidence quality
            confidence = pattern["likelihood"]
            if evidence_count > 2:
                confidence = min(confidence + 0.1, 0.95)
            
            suggestions.append({
                "chain": pattern["chain_name"],
                "impact": pattern["impact"],
                "impact_score": pattern["impact_score"],
                "likelihood": confidence,
                "manual_effort": pattern["manual_effort"],
                "why": pattern["description"],
                "exploitation_steps": pattern["exploitation_steps"],
                "confidence_score": round(confidence * pattern["impact_score"], 2),
                "evidence": evidence,
            })
    
    # Sort by confidence_score (highest first)
    suggestions.sort(key=lambda x: x["confidence_score"], reverse=True)
    
    logger.info(f"Chaining suggestions generated: {len(suggestions)}")
    for s in suggestions[:3]:  # Log top 3
        logger.info(f"  [{s['impact'].upper()}] {s['chain']} (confidence: {s['confidence_score']})")
    
    return suggestions


def get_chain_report(chains: List[Dict]) -> str:
    """
    Generate a human-readable chain report.
    """
    if not chains:
        return "No attack chains identified."
    
    lines = ["# Attack Chain Analysis\n"]
    
    for i, chain in enumerate(chains, 1):
        lines.append(f"## Chain {i}: {chain['chain']}")
        lines.append(f"**Impact:** {chain['impact'].upper()} (Score: {chain['impact_score']}/10)")
        lines.append(f"**Likelihood:** {chain['likelihood']*100:.0f}%")
        lines.append(f"**Manual Effort:** {chain['manual_effort']}")
        lines.append(f"**Confidence Score:** {chain['confidence_score']}")
        lines.append(f"\n### Description")
        lines.append(chain['why'])
        lines.append(f"\n### Exploitation Steps")
        for step in chain.get('exploitation_steps', []):
            lines.append(f"- {step}")
        lines.append("\n---\n")
    
    return "\n".join(lines)


def get_chains_by_impact(chains: List[Dict], min_impact: int = 7) -> List[Dict]:
    """
    Filter chains by minimum impact score.
    """
    return [c for c in chains if c.get("impact_score", 0) >= min_impact]


def get_exploitation_priority(chains: List[Dict]) -> List[str]:
    """
    Get ordered list of chains to exploit first based on confidence.
    """
    sorted_chains = sorted(chains, key=lambda x: x.get("confidence_score", 0), reverse=True)
    return [c["chain"] for c in sorted_chains]
