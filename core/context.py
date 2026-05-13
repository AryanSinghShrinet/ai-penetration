def detect_context(recon_data, logger):
    logger.info("=== Context Detection Started ===")

    context = {
        "application_type": "unknown",
        "response_type": "unknown",
        "likely_vulnerabilities": [],
        "notes": []
    }

    ct = recon_data.get("content_type", "").lower()

    # Response type
    if "html" in ct:
        context["response_type"] = "html"
        context["likely_vulnerabilities"].extend(
            ["xss", "csrf", "open_redirect", "cors", "business_logic"]
        )
    elif "json" in ct:
        context["response_type"] = "json"
        context["likely_vulnerabilities"].extend(
            ["idor", "sqli", "mass_assignment"]
        )
    elif "xml" in ct:
        context["response_type"] = "xml"
        context["likely_vulnerabilities"].append("xxe")

    # Application type
    if recon_data["forms"]:
        context["application_type"] = "web_application"
    elif "/api" in recon_data["target"].lower():
        context["application_type"] = "api"

    # Parameter-based hints
    if any(p.lower() in ["id", "user_id", "account_id"] for p in recon_data["parameters"]):
        context["notes"].append("ID-based parameters detected → IDOR possible")

    if recon_data["forms"]:
        context["notes"].append("Forms detected → input-based vulns possible")

    logger.info(f"Application type: {context['application_type']}")
    logger.info(f"Response type: {context['response_type']}")
    logger.info(f"Likely vulnerabilities: {context['likely_vulnerabilities']}")

    logger.info("=== Context Detection Completed ===")
    return context
