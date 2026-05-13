"""
ML Feature Engineering
========================
Extracts structured feature vectors from HTTP requests/responses
for use in vulnerability prediction models.

This was missing from old project (features were scattered across files).
Centralizes all feature extraction logic in one place.

Feature Groups:
  1. Response features (status, length, timing, headers)
  2. Request features (method, param count, depth)
  3. Content features (entropy, keyword presence, structure)
  4. Behavioral features (diff from baseline)
"""

import re
import math
import hashlib
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------------------------
# Feature Vector Definition
# ---------------------------------------------------------------------------

@dataclass
class VulnFeatureVector:
    """
    Complete feature vector for ML vulnerability prediction.
    All values are numeric (float) for ML model compatibility.
    """

    # Response features
    status_code: float = 200.0
    body_length: float = 0.0
    body_entropy: float = 0.0
    header_count: float = 0.0
    response_time_ms: float = 0.0
    has_content_type: float = 0.0
    has_server_header: float = 0.0
    is_json_response: float = 0.0
    redirect_count: float = 0.0

    # Error signals
    has_error_keywords: float = 0.0
    has_stack_trace: float = 0.0
    has_db_error: float = 0.0
    has_reflection: float = 0.0
    has_version_disclosure: float = 0.0

    # Request features
    param_count: float = 0.0
    url_depth: float = 0.0
    has_id_param: float = 0.0
    has_file_param: float = 0.0
    has_url_param: float = 0.0
    method_risk: float = 0.0        # GET=1, POST=2, PUT=3, DELETE=4

    # Diff features (vs baseline)
    status_diff: float = 0.0
    length_diff: float = 0.0
    length_diff_ratio: float = 0.0

    # Content features
    has_sql_keywords: float = 0.0
    has_html_tags: float = 0.0
    has_script_tags: float = 0.0
    non_printable_ratio: float = 0.0

    def to_vector(self) -> List[float]:
        """Return ordered list of float values for ML input."""
        return list(asdict(self).values())

    @staticmethod
    def feature_names() -> List[str]:
        """Return ordered list of feature names."""
        return list(VulnFeatureVector.__dataclass_fields__.keys())


# ---------------------------------------------------------------------------
# Feature Extractors
# ---------------------------------------------------------------------------

ERROR_KEYWORDS = [
    "exception", "error", "fatal", "warning", "undefined",
    "notice", "traceback", "syntax error", "parse error",
]

DB_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"ora-\d+", r"pg_query",
    r"sqlstate", r"sqlite3", r"unclosed quotation",
    r"you have an error in your sql",
]

STACK_TRACE_PATTERNS = [
    r"at \w+\.\w+\(.*\.java:\d+\)",
    r'File ".*\.py", line \d+',
    r"traceback \(most recent",
]

SQL_KEYWORDS = ["select", "insert", "update", "delete", "drop", "union", "where"]
METHOD_RISK_MAP = {"GET": 1.0, "HEAD": 1.0, "OPTIONS": 1.0, "POST": 2.0, "PUT": 3.0, "PATCH": 3.0, "DELETE": 4.0}


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = defaultdict(int)
    for c in text[:5000]:
        freq[c] += 1
    length = len(text[:5000])
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_response_features(response, response_time_ms: float = 0.0) -> Dict[str, float]:
    """Extract features from an HTTP response object."""
    body = getattr(response, "text", str(response))
    headers = getattr(response, "headers", {})
    status = getattr(response, "status_code", 200)
    history = getattr(response, "history", [])

    body_lower = body.lower()

    return {
        "status_code": float(status),
        "body_length": float(len(body)),
        "body_entropy": _shannon_entropy(body),
        "header_count": float(len(headers)),
        "response_time_ms": response_time_ms,
        "has_content_type": float(bool(headers.get("Content-Type"))),
        "has_server_header": float(bool(headers.get("Server"))),
        "is_json_response": float("application/json" in headers.get("Content-Type", "")),
        "redirect_count": float(len(history)),
        "has_error_keywords": float(any(kw in body_lower for kw in ERROR_KEYWORDS)),
        "has_stack_trace": float(any(re.search(p, body, re.M | re.I) for p in STACK_TRACE_PATTERNS)),
        "has_db_error": float(any(re.search(p, body_lower) for p in DB_ERROR_PATTERNS)),
        "has_version_disclosure": float(bool(re.search(r"(apache|nginx|php|iis)/[\d\.]+", body_lower))),
        "has_html_tags": float(bool(re.search(r"<[a-z]+[^>]*>", body))),
        "has_script_tags": float(bool(re.search(r"<script", body_lower))),
    }


def extract_request_features(
    url: str,
    method: str = "GET",
    payload: str = "",
) -> Dict[str, float]:
    """Extract features from a request."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    path_depth = len([p for p in parsed.path.split("/") if p])

    param_names = list(params.keys())

    return {
        "param_count": float(len(param_names)),
        "url_depth": float(path_depth),
        "has_id_param": float(any(re.search(r"^id$|_id$|uid$", p, re.I) for p in param_names)),
        "has_file_param": float(any(re.search(r"file|path|template|include", p, re.I) for p in param_names)),
        "has_url_param": float(any(re.search(r"url|redirect|next|goto|src", p, re.I) for p in param_names)),
        "method_risk": METHOD_RISK_MAP.get(method.upper(), 1.0),
        "has_sql_keywords": float(any(kw in payload.lower() for kw in SQL_KEYWORDS)),
        "has_reflection": 0.0,  # Filled in later after response comparison
    }


def build_feature_vector(
    url: str,
    method: str,
    payload: str,
    response,
    response_time_ms: float,
    baseline_response=None,
) -> VulnFeatureVector:
    """
    Build a complete feature vector for ML prediction.

    Args:
        baseline_response: Optional baseline response for diff features.
    """
    resp_features = extract_response_features(response, response_time_ms)
    req_features = extract_request_features(url, method, payload)

    # Diff features
    status_diff = 0.0
    length_diff = 0.0
    length_diff_ratio = 0.0
    has_reflection = 0.0

    if baseline_response is not None:
        baseline_status = getattr(baseline_response, "status_code", 200)
        baseline_body = getattr(baseline_response, "text", "")
        current_body = getattr(response, "text", "")

        status_diff = float(abs(resp_features["status_code"] - baseline_status))
        length_diff = float(len(current_body) - len(baseline_body))
        baseline_len = len(baseline_body) or 1
        length_diff_ratio = abs(length_diff) / baseline_len

    # Check payload reflection
    if payload and len(payload) > 3:
        current_body = getattr(response, "text", "").lower()
        has_reflection = float(payload.lower()[:20] in current_body)

    body = getattr(response, "text", "")
    non_printable = sum(1 for c in body if ord(c) < 32 and c not in "\n\r\t")
    non_printable_ratio = non_printable / max(len(body), 1)

    return VulnFeatureVector(
        # Response
        status_code=resp_features["status_code"],
        body_length=resp_features["body_length"],
        body_entropy=resp_features["body_entropy"],
        header_count=resp_features["header_count"],
        response_time_ms=resp_features["response_time_ms"],
        has_content_type=resp_features["has_content_type"],
        has_server_header=resp_features["has_server_header"],
        is_json_response=resp_features["is_json_response"],
        redirect_count=resp_features["redirect_count"],
        # Error signals
        has_error_keywords=resp_features["has_error_keywords"],
        has_stack_trace=resp_features["has_stack_trace"],
        has_db_error=resp_features["has_db_error"],
        has_reflection=has_reflection,
        has_version_disclosure=resp_features["has_version_disclosure"],
        # Request
        param_count=req_features["param_count"],
        url_depth=req_features["url_depth"],
        has_id_param=req_features["has_id_param"],
        has_file_param=req_features["has_file_param"],
        has_url_param=req_features["has_url_param"],
        method_risk=req_features["method_risk"],
        # Diff
        status_diff=status_diff,
        length_diff=length_diff,
        length_diff_ratio=length_diff_ratio,
        # Content
        has_sql_keywords=req_features["has_sql_keywords"],
        has_html_tags=resp_features["has_html_tags"],
        has_script_tags=resp_features["has_script_tags"],
        non_printable_ratio=non_printable_ratio,
    )
