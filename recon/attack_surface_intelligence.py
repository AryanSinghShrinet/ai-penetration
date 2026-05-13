"""
Attack Surface Intelligence Engine
=====================================
Scores and ranks endpoints by vulnerability probability.

This REPLACES the 3-line scoring.py with a proper multi-factor formula
used in real bug bounty automation.

Risk Score Formula:
  score = Σ(factor_weight × factor_value) capped at 100

Factors:
  - Endpoint naming patterns   (0-25 pts)
  - Authentication requirement  (0-20 pts)
  - Parameter complexity        (0-20 pts)
  - HTTP method risk            (0-15 pts)
  - Response behavior signals   (0-10 pts)
  - API structure indicators    (0-10 pts)
"""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict, field
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------------------------
# Pattern libraries for endpoint classification
# ---------------------------------------------------------------------------

HIGH_VALUE_PATTERNS = {
    # Admin / privileged functions
    "admin_panel":    (r"/(admin|administrator|superuser|root|manage|mgmt)", 20),
    "user_data":      (r"/(user|account|profile|me|self|identity)s?/", 18),
    "auth_endpoints": (r"/(login|logout|signin|signout|auth|oauth|token|jwt|sso|saml)", 17),
    "file_ops":       (r"/(upload|download|export|import|attach|file|document|blob)", 16),
    "api_versioned":  (r"/(api|rest|graphql|v\d+)/", 15),
    "payment":        (r"/(payment|billing|checkout|invoice|order|cart|purchase|refund)", 15),
    "config_mgmt":    (r"/(config|settings|preferences|setup|install|init|bootstrap)", 14),
    "debug_diag":     (r"/(debug|test|trace|health|ping|status|diagnostic|phpinfo)", 13),
    "internal":       (r"/(internal|private|secret|hidden|backup|archive|old|temp)", 12),
    "report_data":    (r"/(report|analytics|stats|metrics|log|audit|history)", 10),
}

OWNERSHIP_PARAM_PATTERNS = [
    r"\bid\b", r"_id$", r"^id$", r"userid", r"user_id", r"uid",
    r"account", r"member", r"owner", r"customer", r"client",
    r"token", r"key", r"secret", r"hash", r"guid", r"uuid",
]

INJECTION_PARAM_PATTERNS = {
    "sqli_likely":   (["id", "sort", "order", "filter", "where", "search", "q", "query"], 8),
    "path_traversal":(["file", "path", "dir", "folder", "template", "include", "page"], 7),
    "ssrf_likely":   (["url", "uri", "link", "redirect", "next", "callback", "proxy", "fetch"], 7),
    "ssti_likely":   (["template", "view", "render", "format", "style", "theme"], 6),
    "cmd_likely":    (["cmd", "exec", "run", "command", "shell", "ping", "host", "ip"], 8),
    "idor_likely":   (["id", "user", "account", "doc", "file", "token", "ref"], 6),
}

METHOD_RISK = {
    "DELETE": 15,
    "PUT":    14,
    "PATCH":  13,
    "POST":   10,
    "GET":    5,
    "HEAD":   2,
    "OPTIONS":2,
}


@dataclass
class EndpointScore:
    """Scored endpoint with breakdown of risk factors."""
    endpoint: str
    total_score: float
    risk_level: str           # critical, high, medium, low
    matched_patterns: List[str] = field(default_factory=list)
    parameter_risks: List[str] = field(default_factory=list)
    method_risk: int = 0
    auth_score: int = 0
    parameter_complexity: int = 0
    recommended_tests: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


class AttackSurfaceIntelligence:
    """
    Endpoint Risk Scoring Engine.

    Ingests raw recon data, scores every endpoint, and produces a prioritized
    list so the fuzzer attacks high-value targets first.

    Used in: orchestrator.py → recon → attack surface intelligence → fuzzer
    """

    def __init__(self):
        self._scores: List[EndpointScore] = []

    # -------------------------------------------------------------------------
    # Core Scoring Formula
    # -------------------------------------------------------------------------

    def score_endpoint(
        self,
        endpoint: str,
        methods: Optional[List[str]] = None,
        parameters: Optional[List[str]] = None,
        requires_auth: Optional[bool] = None,
        response_data: Optional[Dict] = None,
    ) -> EndpointScore:
        """
        Score a single endpoint.

        Formula:
          score = naming_score + auth_score + param_score
                  + method_score + response_score + api_score
          max = 100
        """
        score = 0.0
        matched_patterns = []
        param_risks = []
        recommended_tests = []
        methods = methods or ["GET"]
        parameters = parameters or []

        # ------------------------------------------------------------------
        # Factor 1: Endpoint Naming Patterns (0-25 pts)
        # ------------------------------------------------------------------
        naming_score = 0
        path = urlparse(endpoint).path.lower()
        url_params = parse_qs(urlparse(endpoint).query)
        all_params = parameters + list(url_params.keys())

        for pattern_name, (pattern, pts) in HIGH_VALUE_PATTERNS.items():
            if re.search(pattern, endpoint, re.I):
                naming_score = max(naming_score, pts)
                matched_patterns.append(pattern_name)

        naming_score = min(naming_score, 25)
        score += naming_score

        # ------------------------------------------------------------------
        # Factor 2: Authentication Requirement (0-20 pts)
        # ------------------------------------------------------------------
        auth_score = 0
        if requires_auth is True:
            # Authenticated endpoints with ID params = prime IDOR candidates
            auth_score = 15
            has_ownership_param = any(
                re.search(p, param, re.I)
                for param in all_params
                for p in OWNERSHIP_PARAM_PATTERNS
            )
            if has_ownership_param:
                auth_score = 20
                recommended_tests.append("idor")
                matched_patterns.append("auth+ownership_param")
        elif requires_auth is False:
            # Unauthenticated endpoints doing sensitive operations
            if any(p in matched_patterns for p in ["user_data", "payment", "config_mgmt"]):
                auth_score = 18
                matched_patterns.append("sensitive_unauth")
                recommended_tests.append("access_control_bypass")

        score += auth_score

        # ------------------------------------------------------------------
        # Factor 3: Parameter Complexity (0-20 pts)
        # ------------------------------------------------------------------
        param_score = 0
        seen_risks = set()

        for param in all_params:
            for risk_name, (risk_params, pts) in INJECTION_PARAM_PATTERNS.items():
                if any(rp in param.lower() for rp in risk_params) and risk_name not in seen_risks:
                    param_score += pts
                    seen_risks.add(risk_name)
                    param_risks.append(f"{param}→{risk_name}")
                    # Map to test
                    test_map = {
                        "sqli_likely": "sqli",
                        "path_traversal": "lfi",
                        "ssrf_likely": "ssrf",
                        "ssti_likely": "ssti",
                        "cmd_likely": "cmd_injection",
                        "idor_likely": "idor",
                    }
                    if test_map.get(risk_name) not in recommended_tests:
                        recommended_tests.append(test_map[risk_name])

        # Bonus for parameter count (more params = wider attack surface)
        if len(all_params) >= 5:
            param_score += 5
        elif len(all_params) >= 3:
            param_score += 3

        param_score = min(param_score, 20)
        score += param_score

        # ------------------------------------------------------------------
        # Factor 4: HTTP Method Risk (0-15 pts)
        # ------------------------------------------------------------------
        method_score = max((METHOD_RISK.get(m.upper(), 0) for m in methods), default=0)
        method_score = min(method_score, 15)
        score += method_score

        if any(m.upper() in ["PUT", "DELETE", "PATCH"] for m in methods):
            recommended_tests.append("http_method_abuse")

        # ------------------------------------------------------------------
        # Factor 5: Response Behavior Signals (0-10 pts)
        # ------------------------------------------------------------------
        response_score = 0
        if response_data:
            # Different status codes on parameter changes = interesting
            status_codes = response_data.get("status_codes_seen", [])
            if len(set(status_codes)) > 2:
                response_score += 5
            # Response size variation suggests reflection
            sizes = response_data.get("response_sizes", [])
            if sizes and (max(sizes) - min(sizes)) > 500:
                response_score += 5
                recommended_tests.append("xss")

        response_score = min(response_score, 10)
        score += response_score

        # ------------------------------------------------------------------
        # Factor 6: API Structure (0-10 pts)
        # ------------------------------------------------------------------
        api_score = 0
        if re.search(r"/v\d+/", endpoint, re.I):
            api_score += 5
        if re.search(r"\.(json|xml|graphql)$", endpoint, re.I):
            api_score += 5
        if "/graphql" in endpoint.lower():
            api_score += 8
            recommended_tests.append("graphql_introspection")

        api_score = min(api_score, 10)
        score += api_score

        # ------------------------------------------------------------------
        # Determine Risk Level
        # ------------------------------------------------------------------
        total = min(score, 100)
        if total >= 70:
            risk_level = "critical"
        elif total >= 50:
            risk_level = "high"
        elif total >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Add default XSS test for all reflected endpoints
        if not recommended_tests:
            recommended_tests = ["xss", "sqli"]

        return EndpointScore(
            endpoint=endpoint,
            total_score=round(total, 1),
            risk_level=risk_level,
            matched_patterns=list(set(matched_patterns)),
            parameter_risks=param_risks,
            method_risk=method_score,
            auth_score=auth_score,
            parameter_complexity=param_score,
            recommended_tests=list(set(recommended_tests)),
        )

    # -------------------------------------------------------------------------
    # Batch Processing
    # -------------------------------------------------------------------------

    def rank_endpoints(
        self,
        recon_data: Dict,
        logger=None,
    ) -> List[Dict]:
        """
        Score and rank all endpoints from recon data.

        Args:
            recon_data: Dict from recon engine containing:
                - endpoints: list of URLs
                - endpoint_methods: {url: [methods]}
                - parameters: [param_names]
                - forms: [{action, method, inputs}]

        Returns:
            Sorted list of EndpointScore dicts, highest risk first.
        """
        endpoints = recon_data.get("endpoints", [])
        endpoint_methods = recon_data.get("endpoint_methods", {})
        global_params = recon_data.get("parameters", [])

        if logger:
            logger.info(f"[ASI] Scoring {len(endpoints)} endpoints...")

        self._scores = []

        for ep in endpoints:
            methods = endpoint_methods.get(ep, ["GET"])

            # Collect params for this endpoint
            ep_params = list(global_params)
            for form in recon_data.get("forms", []):
                if form.get("action") == ep:
                    ep_params.extend(form.get("inputs", []))

            scored = self.score_endpoint(
                endpoint=ep,
                methods=methods,
                parameters=ep_params,
                requires_auth=None,   # Will be updated after auth probe
            )
            self._scores.append(scored)

        # Sort highest score first
        self._scores.sort(key=lambda x: x.total_score, reverse=True)

        if logger:
            critical = sum(1 for s in self._scores if s.risk_level == "critical")
            high = sum(1 for s in self._scores if s.risk_level == "high")
            logger.info(
                f"[ASI] Ranking complete: {critical} critical, {high} high-risk endpoints"
            )

        return [s.to_dict() for s in self._scores]

    def get_top_targets(self, n: int = 10) -> List[Dict]:
        """Return top N highest-risk endpoints."""
        return [s.to_dict() for s in self._scores[:n]]

    def get_by_risk_level(self, level: str) -> List[Dict]:
        """Filter endpoints by risk level: critical, high, medium, low."""
        return [s.to_dict() for s in self._scores if s.risk_level == level]


def rank_attack_surface(recon_data: Dict, logger=None) -> List[Dict]:
    """Convenience function for use in orchestrator."""
    engine = AttackSurfaceIntelligence()
    return engine.rank_endpoints(recon_data, logger=logger)
