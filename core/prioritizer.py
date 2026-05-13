from core.learning_memory import load_memory, target_key

BASE_WEIGHTS = {
    "xss": 5,
    "sqli": 6,
    "idor": 7,
    "file_upload": 6,
    "cors": 4,
    "business_logic": 8,
    "cmd_injection": 6,
    "ssrf_indicator": 5,
    "oauth_logic": 7
}

MIN_SCORE = 2

def is_api(context):
    return context.get("application_type") == "api"

def has_auth(context):
    return context.get("auth_detected", False)

def compute_score(vuln, context, target):
    score = BASE_WEIGHTS.get(vuln, 1)

    # Context boosts / penalties
    if vuln == "xss" and is_api(context):
        score -= 3  # APIs rarely have XSS

    if vuln == "sqli" and context.get("db_detected"):
        score += 2

    if vuln in ("idor", "business_logic") and has_auth(context):
        score += 3

    if vuln == "cors" and not has_auth(context):
        score -= 2

    # Learning boost
    memory = load_memory()
    tkey = target_key(target)

    if tkey in memory and vuln in memory[tkey]:
        for _, stats in memory[tkey][vuln].items():
            score += stats.get("success", 0)
            score -= stats.get("blocked", 0)

    return score

def prioritize_vulns(vulns, context, target):
    scored = []
    for v in vulns:
        s = compute_score(v, context, target)
        if s >= MIN_SCORE:
            scored.append((v, s))

    scored.sort(key=lambda x: x[1], reverse=True)
    return [v for v, _ in scored]
