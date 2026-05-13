"""
Attack Chain Correlator for AI-Pentester
Builds attack graphs and identifies exploitation chains.
"""

import yaml
from pathlib import Path
from core.chain_graph import AttackGraph, AttackNode

# Load chain patterns from config
def load_chain_patterns():
    """Load chain patterns from YAML config."""
    pattern_path = Path("config/chain_patterns.yaml")
    if pattern_path.exists():
        with open(pattern_path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("chains", [])
    return []

# Fallback hardcoded chains if config not available
CHAIN_RULES = [
    {
        "name": "XSS to Session Hijack",
        "requires": ["xss", "cors"],
        "impact": "Session/token exfiltration",
        "severity": "high",
        "reason": "Unsafe CORS amplifies client-side injection"
    },
    {
        "name": "IDOR to RCE via Upload",
        "requires": ["idor", "file_upload"],
        "impact": "Privilege escalation or RCE",
        "severity": "critical",
        "reason": "Unauthorized object access combined with upload handling"
    },
    {
        "name": "Business Logic to Account Takeover",
        "requires": ["business_logic", "idor"],
        "impact": "Account takeover or workflow abuse",
        "severity": "critical",
        "reason": "Logic flaw allows access to other users' objects"
    },
    {
        "name": "Stored XSS Chain",
        "requires": ["xss", "business_logic"],
        "impact": "Stored attack across workflow",
        "severity": "high",
        "reason": "Injected data reused across trusted steps"
    },
    {
        "name": "SQLi to Admin Access",
        "requires": ["sqli"],
        "impact": "Database compromise, credential theft",
        "severity": "critical",
        "reason": "SQL injection can extract sensitive data"
    },
    {
        "name": "SSRF to Cloud Metadata",
        "requires": ["ssrf_indicator"],
        "impact": "Cloud infrastructure compromise",
        "severity": "critical",
        "reason": "SSRF can access cloud metadata endpoints"
    },
    {
        "name": "Auth Bypass to Privilege Escalation",
        "requires": ["auth_bypass", "idor"],
        "impact": "Unauthorized access to all users",
        "severity": "critical",
        "reason": "Authentication bypass combined with insecure object references"
    },
    {
        "name": "Command Injection to RCE",
        "requires": ["cmd_injection"],
        "impact": "Remote code execution",
        "severity": "critical",
        "reason": "Direct command execution on server"
    },
    {
        "name": "File Upload to Web Shell",
        "requires": ["file_upload"],
        "impact": "Remote code execution",
        "severity": "critical",
        "reason": "Unrestricted file upload allows web shell deployment"
    },
    {
        "name": "OAuth State Bypass",
        "requires": ["oauth_logic", "open_redirect"],
        "impact": "Account takeover",
        "severity": "critical",
        "reason": "OAuth misconfiguration allows token theft"
    },
    {
        "name": "CORS to Token Theft",
        "requires": ["cors"],
        "impact": "Session token exfiltration",
        "severity": "high",
        "reason": "Misconfigured CORS allows cross-origin data theft"
    },
    {
        "name": "XXE to SSRF",
        "requires": ["xxe", "ssrf_indicator"],
        "impact": "Internal network access",
        "severity": "critical",
        "reason": "XXE can trigger SSRF for internal scanning"
    }
]


def correlate(findings, logger):
    """
    Analyze findings and identify attack chains.
    
    Args:
        findings: dict[vuln] -> list of execution results
        logger: Logger instance
    
    Returns:
        (AttackGraph, list of chain suggestions)
    """
    graph = AttackGraph()
    nodes = {}

    # Build attack graph nodes from successful findings
    for vuln, results in findings.items():
        if not isinstance(results, list):
            results = [results]

        for r in results:
            if r.get("status") == "SUCCESS":
                node = AttackNode(
                    vuln=vuln,
                    endpoint=r.get("payload", "unknown"),
                    evidence=r.get("evidence")
                )
                graph.add_node(node)
                nodes.setdefault(vuln, []).append(node)

    # Import chain scoring
    from core.chain_scoring import score_chain
    
    chain_candidates = []
    finding_types = set(findings.keys())
    
    # Load patterns from config first
    config_patterns = load_chain_patterns()
    
    # Process config patterns
    for pattern in config_patterns:
        steps = pattern.get("steps", [])
        required_vulns = [s.get("vuln") for s in steps]
        
        # Check if all required vulns are found
        if all(v in finding_types for v in required_vulns):
            chain = {
                "name": pattern.get("name"),
                "steps": [
                    {"step": i+1, "vuln": s.get("vuln"), "action": s.get("action")}
                    for i, s in enumerate(steps)
                ],
                "severity": pattern.get("severity", "medium"),
                "impact": pattern.get("impact", "")
            }
            chain["score"] = score_chain(chain, findings)
            chain_candidates.append(chain)
            logger.info(f"[correlator] Chain detected: {pattern['name']}")
    
    # Process hardcoded rules as fallback
    for rule in CHAIN_RULES:
        required = rule.get("requires", [])
        
        # Check if any required vulns match
        matches = [v for v in required if v in finding_types]
        
        if matches:
            # Partial match is enough for suggestion
            chain = {
                "name": rule.get("name"),
                "steps": [
                    {"step": i+1, "vuln": v, "action": "Exploit " + v}
                    for i, v in enumerate(required)
                ],
                "severity": rule.get("severity", "medium"),
                "impact": rule.get("impact", ""),
                "reason": rule.get("reason", ""),
                "matched": matches,
                "missing": [v for v in required if v not in finding_types]
            }
            chain["score"] = score_chain(chain, findings)
            
            # Only add if not already in candidates
            existing_names = [c["name"] for c in chain_candidates]
            if chain["name"] not in existing_names:
                chain_candidates.append(chain)
    
    # Sort by score descending
    chain_candidates.sort(key=lambda x: x.get("score", {}).get("total", 0), reverse=True)
    
    logger.info(f"[correlator] Identified {len(chain_candidates)} potential chains")
    
    return graph, chain_candidates


def get_chain_summary(chains):
    """
    Generate a human-readable summary of chains.
    """
    summary = []
    for chain in chains:
        severity = chain.get("severity", "unknown").upper()
        name = chain.get("name", "Unnamed Chain")
        impact = chain.get("impact", "Unknown impact")
        score = chain.get("score", {}).get("total", 0)
        
        summary.append(f"[{severity}] {name} (Score: {score})")
        summary.append(f"  Impact: {impact}")
        
        for step in chain.get("steps", []):
            summary.append(f"    Step {step['step']}: {step['vuln']} - {step['action']}")
        
        summary.append("")
    
    return "\n".join(summary)
