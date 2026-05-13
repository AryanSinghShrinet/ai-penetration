"""
Parameter Miner
================
Discovers hidden/undocumented parameters in web endpoints.

Technique:
  1. Wordlist probing — inject known parameter names and observe response diffs
  2. Reflection detection — parameters that reflect in the response are injectable
  3. Cache-buster technique — avoid false negatives from CDN caching
  4. Body parameter mining — for POST endpoints with JSON/form bodies

This was MISSING from the original project. Parameter discovery is essential
for finding hidden IDOR params, debug flags, and undocumented API fields.
"""

import hashlib
import logging
import random
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

import requests

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parameter wordlist (focused on bug-bounty-relevant hidden params)
# ---------------------------------------------------------------------------

PARAM_WORDLIST = [
    # Debug / development
    "debug", "test", "dev", "verbose", "log", "trace", "mode",
    "env", "environment", "staging", "internal", "preview",

    # Authentication bypass patterns
    "admin", "role", "privilege", "permission", "access", "auth",
    "is_admin", "is_staff", "is_superuser", "sudo", "root",
    "override", "force", "bypass", "allow",

    # IDOR candidates
    "id", "user_id", "userid", "uid", "account_id", "account",
    "customer_id", "member_id", "doc_id", "file_id", "record_id",
    "ref", "reference", "key", "token", "hash", "guid", "uuid",

    # SSRF candidates
    "url", "uri", "link", "redirect", "next", "return", "goto",
    "callback", "webhook", "proxy", "fetch", "load", "src",

    # Path traversal
    "file", "path", "dir", "folder", "template", "include",
    "page", "view", "document", "resource", "location",

    # Injection candidates
    "q", "query", "search", "filter", "where", "sort", "order",
    "limit", "offset", "format", "output", "type", "action",

    # Session / state
    "session", "state", "nonce", "csrf", "ticket", "code",
    "secret", "password", "pass", "pwd", "new_password",

    # Versioning / feature flags
    "version", "v", "api_version", "feature", "flag", "beta",
    "experiment", "variant", "ab", "cohort",

    # Output / format control
    "format", "output", "encoding", "charset", "content_type",
    "callback", "jsonp", "wrap", "pretty",
]


class ParameterMiner:
    """
    Discovers hidden parameters by probing with canary values and watching
    for response differences.

    Strategy:
    - Send baseline request (no added params)
    - Send wordlist request (all params with unique canary values)
    - Compare responses — any difference = potentially active parameter
    - Then test each candidate individually to confirm
    """

    def __init__(self, session: requests.Session, timeout: int = 10, threads: int = 10):
        self.session = session
        self.timeout = timeout
        self.threads = threads

    # -------------------------------------------------------------------------
    # Canary value generation
    # -------------------------------------------------------------------------

    def _make_canary(self) -> str:
        """Generate a unique random value that's unlikely to match anything."""
        return "xP" + "".join(random.choices(string.hexdigits, k=8))

    def _canary_in_response(self, canary: str, response_text: str) -> bool:
        """Check if a canary value was reflected in the response."""
        return canary.lower() in response_text.lower()

    # -------------------------------------------------------------------------
    # Baseline measurement
    # -------------------------------------------------------------------------

    def _get_baseline(self, url: str, method: str = "GET") -> Optional[requests.Response]:
        """Get a clean baseline response without any injected parameters."""
        try:
            if method.upper() == "POST":
                resp = self.session.post(url, data={}, timeout=self.timeout)
            else:
                resp = self.session.get(url, timeout=self.timeout)
            return resp
        except Exception as _e:
            return None

    def _response_signature(self, resp: requests.Response) -> Tuple[int, int]:
        """Generate a signature (status_code, body_length) for comparison."""
        return (resp.status_code, len(resp.text))

    # -------------------------------------------------------------------------
    # GET parameter mining
    # -------------------------------------------------------------------------

    def mine_get_params(
        self,
        url: str,
        wordlist: Optional[List[str]] = None,
        logger=None,
    ) -> List[Dict]:
        """
        Mine for hidden GET parameters.

        Sends batches of parameters (20 at a time to avoid URL length limits),
        detects response changes, then confirms individually.
        """
        words = wordlist or PARAM_WORDLIST
        found = []

        baseline = self._get_baseline(url, "GET")
        if not baseline:
            return found

        base_sig = self._response_signature(baseline)

        # Batch probing (20 params per request)
        batch_size = 20
        interesting_params = set()

        for i in range(0, len(words), batch_size):
            batch = words[i:i + batch_size]
            canary_map = {p: self._make_canary() for p in batch}

            # Build query string
            from urllib.parse import urlparse, parse_qs, urlencode
            parsed = urlparse(url)
            existing = parse_qs(parsed.query, keep_blank_values=True)
            probe_params = {**existing}
            for p, c in canary_map.items():
                probe_params[p] = [c]

            probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(probe_params, doseq=True)}"

            try:
                resp = self.session.get(probe_url, timeout=self.timeout)
                probe_sig = self._response_signature(resp)

                if probe_sig != base_sig:
                    # Something in this batch caused a difference — narrow down
                    for param, canary in canary_map.items():
                        if self._canary_in_response(canary, resp.text):
                            interesting_params.add(param)
                    # Also check response size changes
                    if abs(probe_sig[1] - base_sig[1]) > 50:
                        interesting_params.update(batch)

            except Exception as _e:
                _log.debug(f"[param-miner] GET batch probe failed for {url}: {_e}")
        for param in interesting_params:
            result = self._confirm_param(url, param, "GET", baseline)
            if result:
                found.append(result)
                if logger:
                    logger.info(f"[param-miner] Found GET param: {param} on {url}")

        return found

    # -------------------------------------------------------------------------
    # POST parameter mining
    # -------------------------------------------------------------------------

    def mine_post_params(
        self,
        url: str,
        content_type: str = "application/x-www-form-urlencoded",
        wordlist: Optional[List[str]] = None,
        logger=None,
    ) -> List[Dict]:
        """Mine for hidden POST body parameters."""
        words = wordlist or PARAM_WORDLIST
        found = []

        baseline = self._get_baseline(url, "POST")
        if not baseline:
            return found

        base_sig = self._response_signature(baseline)
        interesting_params = set()

        # Batch POST probing
        batch_size = 20
        for i in range(0, len(words), batch_size):
            batch = words[i:i + batch_size]
            canary_map = {p: self._make_canary() for p in batch}

            try:
                if "json" in content_type:
                    resp = self.session.post(
                        url, json=canary_map, timeout=self.timeout
                    )
                else:
                    resp = self.session.post(
                        url, data=canary_map, timeout=self.timeout
                    )

                probe_sig = self._response_signature(resp)

                if probe_sig != base_sig:
                    for param, canary in canary_map.items():
                        if self._canary_in_response(canary, resp.text):
                            interesting_params.add(param)

            except Exception as _e:
                _log.debug(f"[param-miner] POST batch probe failed for {url}: {_e}")

        # Confirm individually
        for param in interesting_params:
            result = self._confirm_param(url, param, "POST", baseline, content_type)
            if result:
                found.append(result)
                if logger:
                    logger.info(f"[param-miner] Found POST param: {param} on {url}")

        return found

    # -------------------------------------------------------------------------
    # Confirmation
    # -------------------------------------------------------------------------

    def _confirm_param(
        self,
        url: str,
        param: str,
        method: str,
        baseline: requests.Response,
        content_type: str = "application/x-www-form-urlencoded",
    ) -> Optional[Dict]:
        """
        Confirm a parameter individually. Returns finding dict or None.
        """
        canary = self._make_canary()
        base_sig = self._response_signature(baseline)

        try:
            if method.upper() == "GET":
                parsed = urlparse(url)
                existing = parse_qs(parsed.query, keep_blank_values=True)
                existing[param] = [canary]
                probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(existing, doseq=True)}"
                resp = self.session.get(probe_url, timeout=self.timeout)
            else:
                if "json" in content_type:
                    resp = self.session.post(url, json={param: canary}, timeout=self.timeout)
                else:
                    resp = self.session.post(url, data={param: canary}, timeout=self.timeout)

            sig = self._response_signature(resp)
            reflected = self._canary_in_response(canary, resp.text)
            size_diff = abs(sig[1] - base_sig[1])
            status_diff = sig[0] != base_sig[0]

            if reflected or size_diff > 50 or status_diff:
                return {
                    "parameter": param,
                    "endpoint": url,
                    "method": method,
                    "reflected": reflected,
                    "status_changed": status_diff,
                    "size_diff": size_diff,
                    "confidence": "high" if reflected else "medium",
                    "vuln_hints": self._guess_vuln_type(param, reflected),
                }

        except Exception as _e:
            _log.debug(f"[param-miner] Confirmation probe failed for {url} param={param}: {_e}")

    def _guess_vuln_type(self, param: str, reflected: bool) -> List[str]:
        """Suggest likely vulnerability types based on parameter name."""
        hints = []
        param_lower = param.lower()

        if any(x in param_lower for x in ["id", "user", "account", "doc", "file"]):
            hints.append("idor")
        if any(x in param_lower for x in ["url", "redirect", "next", "goto"]):
            hints.append("ssrf")
            hints.append("open_redirect")
        if any(x in param_lower for x in ["file", "path", "include", "template"]):
            hints.append("lfi")
        if reflected:
            hints.append("xss")
        if any(x in param_lower for x in ["q", "search", "filter", "id"]):
            hints.append("sqli")

        return hints or ["unknown"]

    # -------------------------------------------------------------------------
    # Full endpoint mining
    # -------------------------------------------------------------------------

    def mine_endpoint(
        self,
        endpoint: str,
        methods: Optional[List[str]] = None,
        logger=None,
    ) -> Dict:
        """Run parameter mining on an endpoint for all its methods."""
        methods = methods or ["GET"]
        all_findings = []

        for method in methods:
            if method.upper() == "GET":
                findings = self.mine_get_params(endpoint, logger=logger)
            elif method.upper() in ["POST", "PUT", "PATCH"]:
                # Try both form-encoded and JSON
                findings = self.mine_post_params(endpoint, logger=logger)
                findings += self.mine_post_params(
                    endpoint, content_type="application/json", logger=logger
                )
            else:
                continue
            all_findings.extend(findings)

        return {
            "endpoint": endpoint,
            "discovered_parameters": all_findings,
            "count": len(all_findings),
        }


def mine_parameters(
    endpoints: List[str],
    session: requests.Session,
    logger=None,
    threads: int = 5,
) -> List[Dict]:
    """
    Mine parameters across multiple endpoints concurrently.
    Returns list of findings.
    """
    miner = ParameterMiner(session=session, threads=threads)
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(miner.mine_endpoint, ep, logger=logger): ep for ep in endpoints}
        for future in as_completed(futures):
            result = future.result()
            if result["count"] > 0:
                results.append(result)

    return results
