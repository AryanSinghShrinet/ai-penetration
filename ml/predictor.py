import numpy as np
import threading
from core.ml_analysis.data_processing import DatasetBuilder

class VulnerabilityPredictor:
    """Use trained model for prediction"""
    
    def __init__(self, classifier_model, vectorizer):
        # B-11 FIX: Removed redundant self.classifier_model — only self.model used throughout
        self.model = classifier_model
        self.vectorizer = vectorizer
        self.dataset_builder = DatasetBuilder()
    
    def predict_description(self, description, cvss_score: float = 0.0):
        """Predict if a description indicates vulnerability.
        
        Args:
            description: Text description of the potential vulnerability.
            cvss_score: Optional CVSS base score (0.0–10.0). When provided it
                        is used as a feature; when omitted it falls back to 0.0
                        (B-06 FIX: was always hardcoded to 0.0).
        """
        processed = self.dataset_builder.preprocess_text(description)
        text_features = self.vectorizer.transform([processed]).toarray()
        
        # B-06 FIX: Use the caller-supplied cvss_score rather than always 0.0
        text_length = len(processed)
        security_keywords = ['injection', 'xss', 'sql', 'buffer', 'overflow', 'vulnerability', 'exploit', 'attack', 'bypass', 'privilege']
        keyword_count = sum(1 for word in security_keywords if word in processed)
        
        numerical_features = np.array([[cvss_score, text_length, keyword_count]])
        features = np.hstack([text_features, numerical_features])
        
        prediction = self.model.predict(features)
        probabilities = self.model.predict_proba(features)
        
        return {
            'description': description,
            'prediction': 'VULNERABLE' if prediction[0] == 1 else 'SECURE',
            'confidence': float(probabilities[0][1] if prediction[0] == 1 else probabilities[0][0]),
            'vulnerability_probability': float(probabilities[0][1])
        }
    
    def predict_payload_effectiveness(self, payload: str, target_context: dict) -> dict:
        """
        Predict how effective a payload will be against a target.
        
        Args:
            payload: The payload to evaluate
            target_context: Dict with 'technologies', 'vuln_type', 'param_name', etc.
        
        Returns:
            Dict with effectiveness score and recommendation
        """
        # Extract context features
        technologies = target_context.get('technologies', [])
        vuln_type = target_context.get('vuln_type', '')
        param_name = target_context.get('param_name', '')
        
        # Base effectiveness
        effectiveness = 0.5
        reasons = []
        
        # Analyze payload characteristics
        payload_lower = payload.lower()
        
        # SQLi payload analysis
        if vuln_type == 'sqli':
            if any(kw in payload_lower for kw in ["'", '"', '--', 'union', 'select']):
                effectiveness += 0.2
                reasons.append("Contains SQL metacharacters")
            if 'php' in [t.lower() for t in technologies]:
                effectiveness += 0.1
                reasons.append("PHP target - SQLi common")
        
        # XSS payload analysis
        elif vuln_type == 'xss':
            if '<script' in payload_lower or 'onerror' in payload_lower:
                effectiveness += 0.2
                reasons.append("Contains script/event handlers")
            if 'search' in param_name.lower() or 'q' == param_name.lower():
                effectiveness += 0.15
                reasons.append("Search parameter - often reflected")
        
        # Command injection analysis
        elif vuln_type == 'cmd_injection':
            if any(c in payload for c in [';', '|', '`', '$(']):
                effectiveness += 0.2
                reasons.append("Contains shell metacharacters")
            if 'linux' in [t.lower() for t in technologies]:
                effectiveness += 0.1
                reasons.append("Linux target - shell available")
        
        # Payload length penalty
        if len(payload) > 200:
            effectiveness -= 0.1
            reasons.append("Long payload - may be truncated")
        
        # Cap effectiveness
        effectiveness = max(0.1, min(0.95, effectiveness))
        
        return {
            'payload': payload[:50] + '...' if len(payload) > 50 else payload,
            'effectiveness_score': effectiveness,
            'reasons': reasons,
            'recommendation': 'USE' if effectiveness >= 0.5 else 'SKIP'
        }
    
    def rank_payloads(self, payloads: list, target_context: dict) -> list:
        """
        Rank payloads by predicted effectiveness.
        
        Args:
            payloads: List of payloads to rank
            target_context: Context about the target
        
        Returns:
            Sorted list of (payload, score) tuples
        """
        scored = []
        for payload in payloads:
            result = self.predict_payload_effectiveness(payload, target_context)
            scored.append((payload, result['effectiveness_score']))
        
        # Sort by score descending
        return sorted(scored, key=lambda x: x[1], reverse=True)


# =============================================================================
# INTEGRATED ML PREDICTOR - Combines all ML capabilities
# =============================================================================

class IntegratedMLPredictor:
    """
    Unified ML predictor that combines:
    - Description-based prediction
    - Response analysis
    - Payload effectiveness prediction
    - Self-learning integration
    """
    
    def __init__(self):
        self.is_initialized = False
        self._response_analyzer = None
        self._self_learner = None
        
        self._initialize()
    
    def _initialize(self):
        """Initialize ML components."""
        try:
            from core.ml_analysis.response_analyzer import get_response_analyzer
            from core.ml_analysis.self_learner import get_self_learner
            
            self._response_analyzer = get_response_analyzer()
            self._self_learner = get_self_learner()
            self.is_initialized = True
        except Exception as e:
            print(f"[ML] Initialization error: {e}")
            self.is_initialized = False
    
    def analyze_response(self, status: int, headers: dict, body: str, 
                         payload: str = "", vuln_type: str = "") -> dict:
        """
        Analyze an HTTP response for vulnerabilities.
        
        Returns:
            Dict with is_vulnerable, vuln_type, confidence, recommendation
        """
        if not self.is_initialized or self._response_analyzer is None:
            # Fallback to simple rules
            return self._simple_analysis(body, payload)
        
        result = self._response_analyzer.analyze_response(
            status_code=status,
            headers=headers,
            body=body,
            expected_vuln_type=vuln_type,
            payload=payload
        )
        
        return {
            'is_vulnerable': result.is_vulnerable,
            'vuln_type': result.vuln_type,
            'confidence': result.confidence,
            'recommendation': result.recommendation,
            'all_predictions': result.all_predictions
        }
    
    def record_for_learning(self, vuln_type: str, endpoint: str, param: str,
                            payload: str, is_confirmed: bool, status: int,
                            body: str, ml_prediction: str = ""):
        """Record a result for self-learning."""
        if self._self_learner:
            self._self_learner.record_result(
                vuln_type=vuln_type,
                endpoint=endpoint,
                param=param,
                payload=payload,
                is_confirmed=is_confirmed,
                response_status=status,
                response_body=body,
                ml_prediction=ml_prediction
            )
    
    def get_learning_stats(self) -> dict:
        """Get ML learning statistics."""
        if self._self_learner:
            return self._self_learner.get_stats()
        return {}
    
    def _simple_analysis(self, body: str, payload: str) -> dict:
        """Simple rule-based analysis fallback."""
        body_lower = body.lower()
        
        # Check for obvious vulnerability indicators
        indicators = {
            'sqli': ['sql syntax', 'mysql', 'postgresql', 'oracle'],
            'xss': ['<script', 'onerror=', 'javascript:'],
            'cmd': ['uid=', 'root:', '/bin/bash'],
        }
        
        for vuln_type, patterns in indicators.items():
            if any(p in body_lower for p in patterns):
                return {
                    'is_vulnerable': True,
                    'vuln_type': vuln_type,
                    'confidence': 0.7,
                    'recommendation': f'Potential {vuln_type} detected'
                }
        
        return {
            'is_vulnerable': False,
            'vuln_type': 'secure',
            'confidence': 0.6,
            'recommendation': 'Response appears normal'
        }


# FIX P1: Thread-safe singleton — use a lock to prevent double-instantiation
_ml_predictor = None
_ml_predictor_lock = threading.Lock()

def get_ml_predictor() -> IntegratedMLPredictor:
    """Get the integrated ML predictor instance (thread-safe singleton)."""
    global _ml_predictor
    if _ml_predictor is None:
        with _ml_predictor_lock:
            if _ml_predictor is None:  # Double-check inside lock
                _ml_predictor = IntegratedMLPredictor()
    return _ml_predictor
