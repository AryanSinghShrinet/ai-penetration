def map_trust_boundaries(recon_data, logger):
    """
    Layer 5: Trust Boundary Mapping
    Identify if server trusts client-side inputs.
    """
    logger.info("  [5/6] Mapping Trust Boundaries...")
    
    trust_issues = []

    # 1. Check Cookies for Role indicators
    suspicious_keywords = ["admin", "role", "privilege", "level", "debug", "test"]
    
    for cookie in recon_data.get("cookies", []):
        if any(k in cookie.lower() for k in suspicious_keywords):
            trust_issues.append({
                "source": "cookie",
                "name": cookie,
                "risk": "Trust boundary violation (Client-controlled role?)"
            })

    # 2. Check Params
    for param in recon_data.get("parameters", []):
        if any(k in param.lower() for k in suspicious_keywords):
            trust_issues.append({
                "source": "parameter",
                "name": param,
                "risk": "Trust boundary violation (Privilege param)"
            })

    return trust_issues
