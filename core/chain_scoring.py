def score_chain(chain, findings_data):
    """
    Chain Confidence Scoring.
    Calculates likelihood, impact, and effort for a vulnerability chain.
    """
    likelihood_score = 0.0
    impact_score = 0.0
    effort_score = 0.0 # Lower is better? Or scale 0-1 (Low effort - High effort)
    
    # Simple heuristic model
    vuln_weights = {
        "xss": {"impact": 0.6, "likelihood": 0.8},
        "sqli": {"impact": 0.9, "likelihood": 0.5},
        "idor": {"impact": 0.7, "likelihood": 0.6},
        "ssrf_indicator": {"impact": 0.5, "likelihood": 0.4},
        "cmd_injection": {"impact": 1.0, "likelihood": 0.4},
        "file_upload": {"impact": 0.9, "likelihood": 0.5},
        "oauth_logic": {"impact": 0.8, "likelihood": 0.7}
    }
    
    steps = chain["steps"]
    
    # Likelihood: Product of component likelihoods (or min, or avg)
    # Using Avg for now to avoid zeroing out too fast
    l_sum = 0
    i_max = 0
    eff_sum = 0
    
    for step in steps:
        vtype = step["vuln"]
        w = vuln_weights.get(vtype, {"impact": 0.5, "likelihood": 0.5})
        
        l_sum += w["likelihood"]
        i_max = max(i_max, w["impact"])
        eff_sum += 1 # Base effort per step
        
    likelihood = l_sum / len(steps) if steps else 0
    impact = i_max
    
    # Synergies check
    # IDOR + File Upload = Critical Impact boost
    vtypes = [s["vuln"] for s in steps]
    if "idor" in vtypes and "file_upload" in vtypes:
        impact = 1.0
        likelihood += 0.1 # Logical synergy
        
    return {
        "likelihood": round(min(likelihood, 1.0), 2),
        "impact": round(min(impact, 1.0), 2),
        "effort": "Medium" if eff_sum > 1 else "Low"
    }
