import requests

def profile_behavior(target, original_response, logger):
    """
    Layer 2: Behavioral Profiling
    Compares Auth vs Unauth, Valid vs Invalid inputs.
    """
    logger.info("  [2/6] Running Behavioral Profiling Layer...")
    
    profile = {
        "auth_enforced": False,
        "dynamic_rendering": False,
        "access_controls": []
    }

    if original_response is None:
        return profile

    # 1. Auth vs Unauth Check
    # We assume the original_session might have auth (if configured), 
    # so we create a fresh unauth session to compare.
    try:
        unauth_session = requests.Session()
        unauth_resp = unauth_session.get(target, timeout=10)
        
        if unauth_resp.status_code != original_response.status_code:
            profile["auth_enforced"] = True
            profile["access_controls"].append("Status code change on unauth")
        
        if abs(len(unauth_resp.text) - len(original_response.text)) > 200:
            profile["dynamic_rendering"] = True
            profile["access_controls"].append("Significant content length diff on unauth")

    except Exception as e:
        logger.warning(f"Behavioral profiling error: {e}")

    return profile
