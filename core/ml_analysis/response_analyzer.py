"""
HTTP Response Analyzer for ML-Based Vulnerability Detection

This module provides:
1. Neural network model for response classification
2. Multi-class vulnerability prediction
3. Confidence scoring
4. Integration with executor response handling

Uses a simple neural network that can run without TensorFlow/PyTorch
by using scikit-learn's MLPClassifier.
"""

import threading
import numpy as np
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import joblib
import re

# Use sklearn's neural network (works without TensorFlow)
try:
    from sklearn.neural_network import MLPClassifier
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[ML] Warning: scikit-learn not available, ML features disabled")

from core.ml_analysis.training_data import (
    TrainingDataset, 
    ResponseFeatureExtractor, 
    TrainingExample
)


@dataclass
class AnalysisResult:
    """Result of response analysis."""
    is_vulnerable: bool
    vuln_type: str
    confidence: float
    all_predictions: Dict[str, float]
    features_used: Dict
    recommendation: str


class ResponseAnalyzer:
    """
    Analyze HTTP responses to detect vulnerabilities using ML.
    
    Uses an ensemble of:
    - Neural Network (MLP) for complex pattern recognition
    - Random Forest for stable predictions
    - Gradient Boosting for edge cases
    """
    
    VULN_TYPES = [
        "secure",  # Class 0
        "sqli",
        "xss", 
        "ssrf",
        "xxe",
        "cmd_injection",
        "ldap_injection",
        "file_upload",
        "auth_bypass",
        "idor",
        "path_traversal"
    ]
    
    MODEL_DIR = Path("data/ml_models")
    
    def __init__(self):
        self.feature_extractor = ResponseFeatureExtractor()
        self.scaler = StandardScaler()
        self.models = {}
        self.is_trained = False
        
        # Create model directory
        self.MODEL_DIR.mkdir(parents=True, exist_ok=True)
        
        # Try to load existing models
        self._load_models()
        
        # Initialize models if not loaded
        if not self.is_trained and SKLEARN_AVAILABLE:
            self._initialize_models()
    
    def _initialize_models(self):
        """Initialize the ML models."""
        # Neural Network (MLP)
        self.models["mlp"] = MLPClassifier(
            hidden_layer_sizes=(64, 32, 16),
            activation='relu',
            solver='adam',
            max_iter=1000,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1
        )
        
        # Random Forest for stability
        self.models["rf"] = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        # Gradient Boosting for edge cases
        self.models["gb"] = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42
        )
    
    def _load_models(self):
        """Load trained models from disk."""
        try:
            mlp_path = self.MODEL_DIR / "response_mlp.pkl"
            rf_path = self.MODEL_DIR / "response_rf.pkl"
            gb_path = self.MODEL_DIR / "response_gb.pkl"
            scaler_path = self.MODEL_DIR / "response_scaler.pkl"
            
            if all(p.exists() for p in [mlp_path, rf_path, scaler_path]):
                self.models["mlp"] = joblib.load(mlp_path)
                self.models["rf"] = joblib.load(rf_path)
                if gb_path.exists():
                    self.models["gb"] = joblib.load(gb_path)
                self.scaler = joblib.load(scaler_path)
                self.is_trained = True
                print("[ML] Response analyzer models loaded")
        except Exception as e:
            print(f"[ML] Could not load models: {e}")
            self.is_trained = False
    
    def save_models(self):
        """Save trained models to disk."""
        try:
            joblib.dump(self.models.get("mlp"), self.MODEL_DIR / "response_mlp.pkl")
            joblib.dump(self.models.get("rf"), self.MODEL_DIR / "response_rf.pkl")
            if "gb" in self.models:
                joblib.dump(self.models["gb"], self.MODEL_DIR / "response_gb.pkl")
            joblib.dump(self.scaler, self.MODEL_DIR / "response_scaler.pkl")
            print("[ML] Response analyzer models saved")
        except Exception as e:
            print(f"[ML] Error saving models: {e}")
    
    def train(self, dataset: Optional[TrainingDataset] = None):
        """
        Train the models on the dataset.
        
        Args:
            dataset: TrainingDataset instance (or loads default)
        """
        if not SKLEARN_AVAILABLE:
            print("[ML] scikit-learn not available, cannot train")
            return
        
        print("[ML] Training response analyzer...")
        
        # Load or build dataset
        if dataset is None:
            dataset = TrainingDataset()
            if len(dataset.get_all()) < 50:
                print("[ML] Building initial training dataset...")
                dataset.build_initial_dataset()
        
        # Prepare training data
        X, y = self._prepare_training_data(dataset)
        
        if len(X) < 20:
            print("[ML] Not enough training data")
            return
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # D-1 FIX: Fall back to stratify=None when any class has < 2 samples
        # (scikit-learn raises ValueError if a class has only 1 example)
        from collections import Counter
        class_counts = Counter(y)
        use_stratify = y if min(class_counts.values()) >= 2 else None
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=use_stratify
        )
        
        # Train each model
        for name, model in self.models.items():
            print(f"[ML] Training {name}...")
            try:
                model.fit(X_train, y_train)
                
                # Evaluate
                y_pred = model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                print(f"[ML] {name} accuracy: {accuracy:.2%}")
            except Exception as e:
                print(f"[ML] Error training {name}: {e}")
        
        self.is_trained = True
        self.save_models()
        print("[ML] Training complete!")
    
    def _prepare_training_data(self, dataset: TrainingDataset) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data from dataset."""
        X = []
        y = []
        
        for example in dataset.get_all():
            # Extract features
            features = self.feature_extractor.extract_features(
                status_code=example.response_status,
                headers=example.response_headers,
                body=example.response_body,
                payload=example.payload_used
            )
            
            feature_vector = self.feature_extractor.features_to_vector(features)
            X.append(feature_vector)
            
            # Determine label
            if example.is_vulnerable == 0:
                label = 0  # secure
            else:
                # Map vuln_type to class index
                vuln_type = example.vuln_type.lower()
                if vuln_type in self.VULN_TYPES:
                    label = self.VULN_TYPES.index(vuln_type)
                else:
                    label = 1  # generic vulnerable
            
            y.append(label)
        
        return np.array(X), np.array(y)
    
    def analyze_response(self,
                         status_code: int,
                         headers: Dict[str, str],
                         body: str,
                         expected_vuln_type: str = "",
                         payload: str = "") -> AnalysisResult:
        """
        Analyze an HTTP response for vulnerabilities.
        
        Args:
            status_code: HTTP status code
            headers: Response headers
            body: Response body
            expected_vuln_type: Expected vulnerability type (for targeted analysis)
            payload: Payload that was sent
        
        Returns:
            AnalysisResult with predictions and confidence
        """
        # Extract features
        features = self.feature_extractor.extract_features(
            status_code=status_code,
            headers=headers,
            body=body,
            payload=payload
        )
        
        feature_vector = self.feature_extractor.features_to_vector(features)
        
        # If no trained model, use rule-based analysis
        if not self.is_trained or not SKLEARN_AVAILABLE:
            return self._rule_based_analysis(features, body, expected_vuln_type)
        
        # Use ML models
        try:
            X = np.array([feature_vector])
            X_scaled = self.scaler.transform(X)
            
            # Get predictions from each model
            predictions = {}
            probabilities = {}
            
            for name, model in self.models.items():
                try:
                    pred = model.predict(X_scaled)[0]
                    proba = model.predict_proba(X_scaled)[0]
                    predictions[name] = pred
                    probabilities[name] = proba
                except Exception as _e:
                    continue
            
            # Ensemble voting
            if predictions:
                # Count votes
                vote_counts = {}
                for pred in predictions.values():
                    vote_counts[pred] = vote_counts.get(pred, 0) + 1
                
                # Get winner
                final_pred = max(vote_counts, key=vote_counts.get)
                
                # Calculate confidence
                if final_pred == 0:
                    # Secure
                    confidence = sum(p[0] for p in probabilities.values()) / len(probabilities)
                    is_vulnerable = False
                    vuln_type = "secure"
                else:
                    # Vulnerable
                    avg_proba = np.mean([p for p in probabilities.values()], axis=0)
                    confidence = float(max(avg_proba[1:]))  # Exclude secure class
                    is_vulnerable = True
                    vuln_type = self.VULN_TYPES[final_pred] if final_pred < len(self.VULN_TYPES) else "unknown"
                
                # Build all predictions dict
                all_predictions = {}
                avg_proba = np.mean([p for p in probabilities.values()], axis=0)
                for i, vtype in enumerate(self.VULN_TYPES):
                    if i < len(avg_proba):
                        all_predictions[vtype] = float(avg_proba[i])
                
                return AnalysisResult(
                    is_vulnerable=is_vulnerable,
                    vuln_type=vuln_type,
                    confidence=confidence,
                    all_predictions=all_predictions,
                    features_used=features,
                    recommendation=self._get_recommendation(vuln_type, confidence)
                )
        
        except Exception as e:
            print(f"[ML] Error in analysis: {e}")
        
        # Fallback to rule-based
        return self._rule_based_analysis(features, body, expected_vuln_type)
    
    def _rule_based_analysis(self, 
                              features: Dict, 
                              body: str,
                              expected_vuln_type: str) -> AnalysisResult:
        """Fallback rule-based analysis when ML is not available."""
        body_lower = body.lower()
        
        # Check for specific vulnerability patterns
        vuln_indicators = {
            "sqli": ["sql syntax", "mysql", "postgresql", "oracle", "sqlite", "odbc"],
            "xss": ["<script", "onerror=", "onload=", "javascript:"],
            "cmd_injection": ["uid=", "root:", "bin/bash", "c:\\windows"],
            "xxe": ["<!entity", "<!doctype", "/etc/passwd"],
            "ssrf": ["169.254.169.254", "localhost", "127.0.0.1"],
            "path_traversal": ["../", "..\\", "/etc/passwd"],
        }
        
        detected_vulns = {}
        for vuln_type, indicators in vuln_indicators.items():
            count = sum(1 for ind in indicators if ind in body_lower)
            if count > 0:
                detected_vulns[vuln_type] = count
        
        if detected_vulns:
            best_match = max(detected_vulns, key=detected_vulns.get)
            confidence = min(0.5 + (detected_vulns[best_match] * 0.15), 0.95)
            
            return AnalysisResult(
                is_vulnerable=True,
                vuln_type=best_match,
                confidence=confidence,
                all_predictions={k: 0.0 for k in self.VULN_TYPES},
                features_used=features,
                recommendation=self._get_recommendation(best_match, confidence)
            )
        
        # Check for generic error indicators
        if features.get("has_error_message") or features.get("has_stack_trace"):
            return AnalysisResult(
                is_vulnerable=True,
                vuln_type="info_disclosure",
                confidence=0.6,
                all_predictions={k: 0.0 for k in self.VULN_TYPES},
                features_used=features,
                recommendation="Review error message for sensitive information"
            )
        
        # Secure
        return AnalysisResult(
            is_vulnerable=False,
            vuln_type="secure",
            confidence=0.8,
            all_predictions={"secure": 0.8},
            features_used=features,
            recommendation="Response appears secure"
        )
    
    def _get_recommendation(self, vuln_type: str, confidence: float) -> str:
        """Get recommendation based on vulnerability type."""
        recommendations = {
            "sqli": "Use parameterized queries and input validation",
            "xss": "Implement output encoding and Content-Security-Policy",
            "cmd_injection": "Avoid shell commands, use safe APIs",
            "xxe": "Disable DTDs and external entities in XML parser",
            "ssrf": "Whitelist allowed URLs and block internal IPs",
            "ldap_injection": "Escape LDAP special characters",
            "file_upload": "Validate file types and store outside webroot",
            "auth_bypass": "Implement proper authentication checks",
            "idor": "Add authorization checks for all resources",
            "path_traversal": "Validate and sanitize file paths",
            "secure": "Response appears secure, continue monitoring"
        }
        
        base_rec = recommendations.get(vuln_type, "Review for potential vulnerabilities")
        
        if confidence >= 0.9:
            return f"HIGH CONFIDENCE: {base_rec}"
        elif confidence >= 0.7:
            return f"MEDIUM CONFIDENCE: {base_rec}"
        else:
            return f"LOW CONFIDENCE: {base_rec}"
    
    def batch_analyze(self, responses: List[Dict]) -> List[AnalysisResult]:
        """
        Analyze multiple responses in batch.
        
        Args:
            responses: List of dicts with 'status', 'headers', 'body', 'payload'
        
        Returns:
            List of AnalysisResult
        """
        results = []
        for resp in responses:
            result = self.analyze_response(
                status_code=resp.get("status", 200),
                headers=resp.get("headers", {}),
                body=resp.get("body", ""),
                expected_vuln_type=resp.get("vuln_type", ""),
                payload=resp.get("payload", "")
            )
            results.append(result)
        return results
    
    def get_model_info(self) -> Dict:
        """Get information about the trained models."""
        info = {
            "is_trained": self.is_trained,
            "models": list(self.models.keys()),
            "vuln_types": self.VULN_TYPES,
            "feature_count": 21  # Number of features in vector
        }
        
        if self.is_trained:
            for name, model in self.models.items():
                if hasattr(model, "n_estimators"):
                    info[f"{name}_trees"] = model.n_estimators
                if hasattr(model, "hidden_layer_sizes"):
                    info[f"{name}_layers"] = model.hidden_layer_sizes
        
        return info


# =============================================================================
# QUICK ANALYZER FOR PIPELINE USE
# =============================================================================

_analyzer_instance = None
# B-04 FIX: Add lock to prevent race condition in multi-threaded scans
_analyzer_lock = threading.Lock()

def get_response_analyzer() -> ResponseAnalyzer:
    """Get singleton response analyzer instance (thread-safe)."""
    global _analyzer_instance
    if _analyzer_instance is None:
        with _analyzer_lock:
            # Double-check inside lock to prevent duplicate instantiation
            if _analyzer_instance is None:
                _analyzer_instance = ResponseAnalyzer()
    return _analyzer_instance


def quick_analyze(status: int, headers: Dict, body: str, payload: str = "") -> Dict:
    """
    Quick analysis for use in executor.
    
    Returns simple dict with vulnerability assessment.
    """
    analyzer = get_response_analyzer()
    result = analyzer.analyze_response(status, headers, body, payload=payload)
    
    return {
        "is_vulnerable": result.is_vulnerable,
        "vuln_type": result.vuln_type,
        "confidence": result.confidence,
        "recommendation": result.recommendation
    }


def train_response_analyzer():
    """Train the response analyzer with default dataset."""
    analyzer = ResponseAnalyzer()
    analyzer.train()
    return analyzer.get_model_info()


if __name__ == "__main__":
    # Train and test the analyzer
    print("Training Response Analyzer...")
    analyzer = ResponseAnalyzer()
    analyzer.train()
    
    # Test with sample responses
    print("\nTesting with sample responses...")
    
    # SQLi test
    result = analyzer.analyze_response(
        500, {},
        "Error: You have an error in your SQL syntax near 'test'",
        expected_vuln_type="sqli"
    )
    print(f"SQLi test: {result.vuln_type} (confidence: {result.confidence:.2%})")
    
    # XSS test
    result = analyzer.analyze_response(
        200, {},
        "<html>Search: <script>alert(1)</script></html>",
        expected_vuln_type="xss"
    )
    print(f"XSS test: {result.vuln_type} (confidence: {result.confidence:.2%})")
    
    # Secure test
    result = analyzer.analyze_response(
        200, {"Content-Type": "text/html"},
        "<html>Welcome to our website</html>"
    )
    print(f"Secure test: {result.vuln_type} (confidence: {result.confidence:.2%})")
