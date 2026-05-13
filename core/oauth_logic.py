def analyze_oauth_parameters(params):
    issues = []

    if "state" not in params:
        issues.append("Missing CSRF state parameter")

    if "redirect_uri" in params:
        if "*" in params.get("redirect_uri", ""):
            issues.append("Wildcard redirect_uri")

    if params.get("response_type") == "token":
        issues.append("Implicit OAuth flow used")

    if "scope" in params and "admin" in params.get("scope", "").lower():
        issues.append("Overly broad OAuth scope")

    return issues
