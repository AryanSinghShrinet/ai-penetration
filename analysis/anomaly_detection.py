"""
Response Anomaly Detection Engine
===================================
Detects behavioral anomalies in HTTP responses without relying on
known vulnerability signatures.

This is the "detect unknown vulnerabilities" component.

Approaches:
  1. Statistical Baseline — build a distribution of normal responses,
     flag outliers using z-score / IQR
  2. Isolation Forest — unsupervised anomaly detection on response features
  3. Entropy Analysis — high entropy in specific response parts = interesting
  4. Timing Oracle — statistical detection of time-based blind injections
  5. Response Clustering — DBSCAN to group responses; singletons = anomalies

Why this matters: Signature-based scanners miss novel vulnerabilities.
Anomaly detection finds bugs that have no CVE yet.
"""

import math
import re
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Feature Extraction from HTTP Responses
# ---------------------------------------------------------------------------

@dataclass
class ResponseFeatures:
    """Numeric feature vector extracted from an HTTP response."""
    status_code: int
    body_length: int
    body_entropy: float
    header_count: int
    has_error_keywords: int   # 0 or 1
    has_stack_trace: int
    has_server_info: int
    response_time_ms: float
    redirect_count: int
    content_type_id: int      # Encoded content type

    def to_vector(self) -> List[float]:
        return [
            float(self.status_code),
            float(self.body_length),
            self.body_entropy,
            float(self.header_count),
            float(self.has_error_keywords),
            float(self.has_stack_trace),
            float(self.has_server_info),
            self.response_time_ms,
            float(self.redirect_count),
            float(self.content_type_id),
        ]

    def to_dict(self) -> Dict:
        return asdict(self)


# Common error patterns that suggest vulnerability exposure
ERROR_PATTERNS = [
    r"exception", r"traceback", r"stack trace", r"error on line",
    r"undefined variable", r"fatal error", r"internal server error",
    r"syntax error", r"null pointer", r"index out of bounds",
    r"access violation", r"segmentation fault",
]

STACK_TRACE_PATTERNS = [
    r"at \w+\.\w+\(.*\.java:\d+\)",   # Java
    r"File \".*\.py\", line \d+",      # Python
    r"#\d+ .* in .*\(\)",              # C/C++
    r"System\..*Exception",            # .NET
    r"Traceback \(most recent call",   # Python
]

SERVER_INFO_PATTERNS = [
    r"Apache/[\d\.]+", r"nginx/[\d\.]+", r"PHP/[\d\.]+",
    r"ASP\.NET version", r"Python/[\d\.]+", r"Ruby[\d\.]+",
    r"IIS/[\d\.]+", r"Jetty/[\d\.]+",
]

CONTENT_TYPE_MAP = {
    "text/html": 1,
    "application/json": 2,
    "application/xml": 3,
    "text/plain": 4,
    "text/xml": 5,
}


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = defaultdict(int)
    for c in text:
        freq[c] += 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features(response, response_time_ms: float = 0.0) -> ResponseFeatures:
    """Extract a numeric feature vector from an HTTP response."""
    body = response.text if hasattr(response, "text") else str(response)
    headers = response.headers if hasattr(response, "headers") else {}
    status = response.status_code if hasattr(response, "status_code") else 200

    body_lower = body.lower()

    has_errors = int(any(re.search(p, body_lower) for p in ERROR_PATTERNS))
    has_trace = int(any(re.search(p, body, re.M) for p in STACK_TRACE_PATTERNS))
    has_server = int(any(re.search(p, body) for p in SERVER_INFO_PATTERNS))
    has_server |= int(bool(headers.get("Server", "")))

    ct = headers.get("Content-Type", "text/html").split(";")[0].strip().lower()
    ct_id = CONTENT_TYPE_MAP.get(ct, 0)

    # Only compute entropy on response body (cap at 5000 chars for speed)
    entropy = _shannon_entropy(body[:5000])

    redirect_count = 0
    if hasattr(response, "history"):
        redirect_count = len(response.history)

    return ResponseFeatures(
        status_code=status,
        body_length=len(body),
        body_entropy=entropy,
        header_count=len(headers),
        has_error_keywords=has_errors,
        has_stack_trace=has_trace,
        has_server_info=has_server,
        response_time_ms=response_time_ms,
        redirect_count=redirect_count,
        content_type_id=ct_id,
    )


# ---------------------------------------------------------------------------
# Statistical Anomaly Detector
# ---------------------------------------------------------------------------

@dataclass
class AnomalyReport:
    """Result of anomaly analysis for a response."""
    is_anomalous: bool
    anomaly_score: float          # 0.0 (normal) to 1.0 (highly anomalous)
    anomaly_reasons: List[str]
    features: Dict
    timing_anomaly: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


class StatisticalAnomalyDetector:
    """
    Builds a statistical baseline from normal responses and flags deviations.

    Uses:
    - Z-score for continuous features (body_length, response_time)
    - Binary checks for error keywords and stack traces
    - Entropy thresholds for detecting unusual content
    """

    def __init__(self, z_threshold: float = 3.0):
        self.z_threshold = z_threshold
        self._baseline_lengths: List[float] = []
        self._baseline_times: List[float] = []
        self._baseline_entropies: List[float] = []

    def add_baseline_response(self, response, response_time_ms: float) -> None:
        """Add a normal response to build the baseline distribution."""
        features = extract_features(response, response_time_ms)
        self._baseline_lengths.append(features.body_length)
        self._baseline_times.append(response_time_ms)
        self._baseline_entropies.append(features.body_entropy)

    def _z_score(self, value: float, data: List[float]) -> float:
        """Calculate z-score of a value given a distribution."""
        if len(data) < 3:
            return 0.0
        mean = statistics.mean(data)
        stdev = statistics.stdev(data) or 1.0
        return abs((value - mean) / stdev)

    def analyze(self, response, response_time_ms: float) -> AnomalyReport:
        """Analyze a response against the established baseline."""
        features = extract_features(response, response_time_ms)
        reasons = []
        score = 0.0

        # Check 1: Body length anomaly
        if self._baseline_lengths:
            z = self._z_score(features.body_length, self._baseline_lengths)
            if z > self.z_threshold:
                reasons.append(f"body_length_outlier (z={z:.1f})")
                score += min(z / 10, 0.3)

        # Check 2: Timing anomaly (time-based blind injection signal)
        timing_anomaly = False
        if self._baseline_times:
            z_time = self._z_score(response_time_ms, self._baseline_times)
            if z_time > self.z_threshold and response_time_ms > 3000:
                reasons.append(f"timing_anomaly (z={z_time:.1f}, {response_time_ms:.0f}ms)")
                score += 0.35
                timing_anomaly = True

        # Check 3: Error keywords (always anomalous)
        if features.has_error_keywords:
            reasons.append("error_keywords_detected")
            score += 0.3

        # Check 4: Stack trace (almost certainly a bug)
        if features.has_stack_trace:
            reasons.append("stack_trace_exposed")
            score += 0.4

        # Check 5: Server version disclosure
        if features.has_server_info:
            reasons.append("server_version_disclosed")
            score += 0.1

        # Check 6: Entropy anomaly (unusually high entropy = encoded data?)
        if self._baseline_entropies:
            z_ent = self._z_score(features.body_entropy, self._baseline_entropies)
            if z_ent > self.z_threshold:
                reasons.append(f"entropy_outlier (z={z_ent:.1f})")
                score += 0.15

        score = min(score, 1.0)

        return AnomalyReport(
            is_anomalous=score > 0.3,
            anomaly_score=round(score, 3),
            anomaly_reasons=reasons,
            features=features.to_dict(),
            timing_anomaly=timing_anomaly,
        )


# ---------------------------------------------------------------------------
# Isolation Forest Anomaly Detector (ML-based)
# ---------------------------------------------------------------------------

class IsolationForestDetector:
    """
    ML-based anomaly detection using Isolation Forest.

    Train on a set of "normal" responses, then flag responses that
    the model isolates quickly (i.e., outliers).
    """

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self._model = None
        self._scaler = None
        self._training_data: List[List[float]] = []
        self._trained = False

    def add_training_sample(self, response, response_time_ms: float = 0.0) -> None:
        """Add a normal response to the training set."""
        features = extract_features(response, response_time_ms)
        self._training_data.append(features.to_vector())

    def train(self, logger=None) -> bool:
        """Train the Isolation Forest model."""
        if not SKLEARN_AVAILABLE:
            if logger:
                logger.warning("[anomaly] scikit-learn not available, Isolation Forest disabled")
            return False

        if len(self._training_data) < 5:
            if logger:
                logger.warning("[anomaly] Not enough training samples for Isolation Forest")
            return False

        import numpy as np

        X = np.array(self._training_data)
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self._model.fit(X_scaled)
        self._trained = True

        if logger:
            logger.info(f"[anomaly] Isolation Forest trained on {len(self._training_data)} samples")

        return True

    def predict(self, response, response_time_ms: float = 0.0) -> AnomalyReport:
        """Predict whether a response is anomalous."""
        features = extract_features(response, response_time_ms)

        if not self._trained or not SKLEARN_AVAILABLE:
            # Fall back to heuristic
            is_anomalous = features.has_stack_trace or features.has_error_keywords
            return AnomalyReport(
                is_anomalous=bool(is_anomalous),
                anomaly_score=0.5 if is_anomalous else 0.0,
                anomaly_reasons=["ml_not_available"],
                features=features.to_dict(),
            )

        import numpy as np
        X = np.array([features.to_vector()])
        X_scaled = self._scaler.transform(X)

        # Isolation Forest: -1 = outlier, 1 = normal
        prediction = self._model.predict(X_scaled)[0]
        score_raw = self._model.score_samples(X_scaled)[0]

        # Convert to 0-1 anomaly score (more negative = more anomalous)
        anomaly_score = min(max((-score_raw - 0.4) * 2, 0), 1.0)

        reasons = []
        if prediction == -1:
            reasons.append("isolation_forest_outlier")
        if features.has_error_keywords:
            reasons.append("error_keywords")
        if features.has_stack_trace:
            reasons.append("stack_trace")

        return AnomalyReport(
            is_anomalous=prediction == -1,
            anomaly_score=round(anomaly_score, 3),
            anomaly_reasons=reasons,
            features=features.to_dict(),
        )


# ---------------------------------------------------------------------------
# Combined Detector (recommended for production use)
# ---------------------------------------------------------------------------

class AnomalyDetectionEngine:
    """
    Combines statistical and ML-based anomaly detection.

    Use this in the main scanning pipeline.
    """

    def __init__(self):
        self.statistical = StatisticalAnomalyDetector()
        self.isolation_forest = IsolationForestDetector()
        self._baseline_count = 0
        self._trained = False

    def learn_baseline(self, response, response_time_ms: float = 0.0) -> None:
        """Feed a normal response into both detectors."""
        self.statistical.add_baseline_response(response, response_time_ms)
        self.isolation_forest.add_training_sample(response, response_time_ms)
        self._baseline_count += 1

    def finalize_baseline(self, logger=None) -> None:
        """Train ML model after collecting enough baseline samples."""
        if self._baseline_count >= 5:
            self._trained = self.isolation_forest.train(logger=logger)

    def analyze(self, response, response_time_ms: float = 0.0) -> AnomalyReport:
        """
        Analyze a response using both detectors.
        Returns the report with the higher anomaly score.
        """
        stat_report = self.statistical.analyze(response, response_time_ms)

        if self._trained:
            ml_report = self.isolation_forest.predict(response, response_time_ms)
            # Use the higher-confidence report
            if ml_report.anomaly_score > stat_report.anomaly_score:
                return ml_report

        return stat_report

    @property
    def is_ready(self) -> bool:
        return self._baseline_count >= 3


def create_anomaly_engine() -> AnomalyDetectionEngine:
    """Factory function."""
    return AnomalyDetectionEngine()
