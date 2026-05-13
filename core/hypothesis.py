def generate_hypotheses(profile):
    """
    Vulnerability Hypothesis Engine.
    Analyzes ReconProfile to generate structured vulnerability hypotheses.
    """
    hypotheses = []
    
    # 1. IDOR Hypothesis
    # If we have entities (user_id, order_id) and behavioral auth checks
    if profile.entities:
        c = 0.6 # Base confidence
        reasons = ["Entities detected"]
        
        # Check if auth is enforced (from behavioral profile if available)
        # We need to access profile.behavior or similar if we stored it
        # For now, relying on entities existence as primary signal per design
        
        hypotheses.append({
            "type": "IDOR",
            "reason": "Ownership entities detected (potential IDOR)",
            "confidence": c,
            "required_checks": ["cross-user ID swap"],
            "manual_attention": True
        })

    # 2. Auth Bypass Hypothesis
    # If profile has behavioral data indicating weak auth differentiation
    # We stored behavioral profile in profile.hypotheses (from recon/__init__.py)
    # Let's check existing hypotheses in profile
    for h in profile.hypotheses:
        if h["type"] == "auth_bypass":
            # Enhance it
            hypotheses.append({
                "type": "Auth Bypass",
                "reason": h["evidence"],
                "confidence": 0.5, # Medium confidence
                "required_checks": ["direct object access", "header manipulation"],
                "manual_attention": True
            })

    # 3. Logic Flaw Hypothesis
    # If workflow graph has non-linear paths or many nodes
    if profile.workflows and len(profile.workflows.get("nodes", [])) > 2:
        hypotheses.append({
            "type": "Business Logic Flaw",
            "reason": f"Complex workflow detected ({len(profile.workflows['nodes'])} steps)",
            "confidence": 0.7,
            "required_checks": ["skip step", "repeat step"],
            "manual_attention": True
        })

    # 4. Tech-Stack Specific
    if "php" in profile.technologies:
        hypotheses.append({
            "type": "PHP Deserialization",
            "reason": "PHP detected",
            "confidence": 0.3, # Low unless we see serialized obj
            "required_checks": ["phar:// wrapper", "object injection"],
            "manual_attention": False
        })
        
    return hypotheses
