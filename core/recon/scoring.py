def calculate_risk_scores(recon_data, logger):
    """
    Layer 6: Intelligence Scoring
    Prioritize endpoints based on signals.
    """
    logger.info("  [6/6] Calculating Risk Scores...")
    
    ranked_targets = []
    
    for url in recon_data.get("endpoints", []):
        score = 0
        reasons = []
        
        # Base value
        score += 1
        
        # Factors
        if any(x in url for x in ["admin", "api", "v1", "config", "upload"]):
            score += 3
            reasons.append("High-value keyword")
            
        if "id=" in url or "_id" in url:
            score += 2
            reasons.append("Ownership parameter")
            
        ranked_targets.append({
            "endpoint": url,
            "risk_score": score,
            "reasons": reasons
        })
        
    # Sort by score desc
    ranked_targets.sort(key=lambda x: x["risk_score"], reverse=True)
    return ranked_targets
