"""
Self-Learning System for AI-Pentester

This module provides:
1. Feedback loop from scan results
2. Incremental model updates
3. Performance tracking over time
4. Learning state persistence

The self-learner collects confirmed vulnerabilities and uses them
to improve the ML model's predictions over time.
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
import threading

from core.ml_analysis.training_data import TrainingDataset, TrainingExample


@dataclass
class LearningEvent:
    """A single learning event from a scan result."""
    id: str
    timestamp: str
    vuln_type: str
    endpoint: str
    param: str
    payload: str
    is_confirmed: bool
    confidence: float
    response_status: int
    response_body_hash: str
    ml_prediction: str
    ml_confidence: float
    prediction_correct: bool
    

@dataclass
class LearningStats:
    """Statistics for the learning system."""
    total_events: int = 0
    correct_predictions: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    accuracy: float = 0.0
    last_training_time: str = ""
    model_version: int = 0
    by_vuln_type: Dict[str, Dict] = field(default_factory=dict)


class SelfLearner:
    """
    Self-learning system that improves ML predictions over time.
    
    Collects confirmed scan results, updates training data,
    and triggers model retraining when appropriate.
    """
    
    LEARNING_DIR = Path("data/learning")
    EVENTS_FILE = "learning_events.json"
    STATS_FILE = "learning_stats.json"
    
    # Threshold for triggering retraining
    RETRAIN_THRESHOLD = 50  # New examples before retrain
    MIN_ACCURACY_THRESHOLD = 0.7  # Retrain if accuracy drops below this
    
    def __init__(self):
        self.learning_dir = self.LEARNING_DIR
        self.learning_dir.mkdir(parents=True, exist_ok=True)
        
        self.events: List[LearningEvent] = []
        self.stats = LearningStats()
        self.pending_examples: List[TrainingExample] = []
        
        self._lock = threading.Lock()
        
        # Load existing data
        self._load_events()
        self._load_stats()
    
    def _load_events(self):
        """Load existing learning events."""
        events_file = self.learning_dir / self.EVENTS_FILE
        if events_file.exists():
            try:
                with open(events_file, "r") as f:
                    data = json.load(f)
                    for item in data[-1000:]:  # Keep last 1000 events
                        self.events.append(LearningEvent(**item))
            except Exception as e:
                print(f"[SelfLearner] Error loading events: {e}")
    
    def _load_stats(self):
        """Load learning statistics."""
        stats_file = self.learning_dir / self.STATS_FILE
        if stats_file.exists():
            try:
                with open(stats_file, "r") as f:
                    data = json.load(f)
                    self.stats = LearningStats(
                        total_events=data.get("total_events", 0),
                        correct_predictions=data.get("correct_predictions", 0),
                        false_positives=data.get("false_positives", 0),
                        false_negatives=data.get("false_negatives", 0),
                        accuracy=data.get("accuracy", 0.0),
                        last_training_time=data.get("last_training_time", ""),
                        model_version=data.get("model_version", 0),
                        by_vuln_type=data.get("by_vuln_type", {})
                    )
            except Exception as e:
                print(f"[SelfLearner] Error loading stats: {e}")
    
    def save(self):
        """Save learning data to disk."""
        with self._lock:
            # Save events
            events_file = self.learning_dir / self.EVENTS_FILE
            events_data = [asdict(e) for e in self.events[-1000:]]
            with open(events_file, "w") as f:
                json.dump(events_data, f, indent=2)
            
            # Save stats
            stats_file = self.learning_dir / self.STATS_FILE
            stats_data = asdict(self.stats)
            with open(stats_file, "w") as f:
                json.dump(stats_data, f, indent=2)
    
    def record_result(self,
                      vuln_type: str,
                      endpoint: str,
                      param: str,
                      payload: str,
                      is_confirmed: bool,
                      response_status: int,
                      response_body: str,
                      ml_prediction: str = "",
                      ml_confidence: float = 0.0):
        """
        Record a scan result for learning.
        
        Args:
            vuln_type: Type of vulnerability tested
            endpoint: Target endpoint
            param: Parameter tested
            payload: Payload used
            is_confirmed: Whether vulnerability was confirmed
            response_status: HTTP status code
            response_body: Response body
            ml_prediction: What ML predicted (if available)
            ml_confidence: ML prediction confidence
        """
        # Generate event ID
        event_id = hashlib.md5(
            f"{endpoint}{param}{payload}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]
        
        # Hash response body for storage efficiency
        body_hash = hashlib.md5(response_body.encode()).hexdigest()[:16]
        
        # Determine if prediction was correct
        prediction_correct = False
        if ml_prediction:
            if is_confirmed and ml_prediction != "secure":
                prediction_correct = True
            elif not is_confirmed and ml_prediction == "secure":
                prediction_correct = True
        
        # Create event
        event = LearningEvent(
            id=event_id,
            timestamp=datetime.now().isoformat(),
            vuln_type=vuln_type,
            endpoint=endpoint,
            param=param,
            payload=payload,
            is_confirmed=is_confirmed,
            confidence=1.0 if is_confirmed else 0.5,
            response_status=response_status,
            response_body_hash=body_hash,
            ml_prediction=ml_prediction,
            ml_confidence=ml_confidence,
            prediction_correct=prediction_correct
        )
        
        with self._lock:
            self.events.append(event)
            self._update_stats(event, response_body)

        # Add to pending training examples
        self._add_training_example(
            vuln_type=vuln_type,
            endpoint=endpoint,
            payload=payload,
            is_vulnerable=is_confirmed,
            response_status=response_status,
            response_body=response_body
        )

        # FIX SL1: Schedule retrain in a background thread to avoid blocking active scan threads
        if len(self.pending_examples) >= self.RETRAIN_THRESHOLD:
            retrain_thread = threading.Thread(
                target=self._trigger_retrain,
                daemon=True,
                name="SelfLearner-Retrain"
            )
            retrain_thread.start()
    
    def _update_stats(self, event: LearningEvent, response_body: str):
        """Update learning statistics."""
        self.stats.total_events += 1
        
        if event.prediction_correct:
            self.stats.correct_predictions += 1
        elif event.is_confirmed and event.ml_prediction == "secure":
            self.stats.false_negatives += 1
        elif not event.is_confirmed and event.ml_prediction != "secure":
            self.stats.false_positives += 1
        
        # Update accuracy
        if self.stats.total_events > 0:
            self.stats.accuracy = self.stats.correct_predictions / self.stats.total_events
        
        # Update by vuln type
        if event.vuln_type:
            if event.vuln_type not in self.stats.by_vuln_type:
                self.stats.by_vuln_type[event.vuln_type] = {
                    "total": 0,
                    "confirmed": 0,
                    "correct_predictions": 0
                }
            
            self.stats.by_vuln_type[event.vuln_type]["total"] += 1
            if event.is_confirmed:
                self.stats.by_vuln_type[event.vuln_type]["confirmed"] += 1
            if event.prediction_correct:
                self.stats.by_vuln_type[event.vuln_type]["correct_predictions"] += 1
    
    def _add_training_example(self,
                               vuln_type: str,
                               endpoint: str,
                               payload: str,
                               is_vulnerable: bool,
                               response_status: int,
                               response_body: str):
        """Add a training example to pending list."""
        example = TrainingExample(
            id="",
            description=f"{'Confirmed' if is_vulnerable else 'Not'} {vuln_type} at {endpoint}",
            response_body=response_body[:5000],
            response_status=response_status,
            vuln_type=vuln_type,
            payload_used=payload,
            is_vulnerable=1 if is_vulnerable else 0,
            confidence=0.9 if is_vulnerable else 0.8,
            source="scan_result",
            cvss_score=7.0 if is_vulnerable else 0.0
        )
        
        with self._lock:
            self.pending_examples.append(example)
    
    def _trigger_retrain(self):
        """Trigger model retraining with new data."""
        if not self.pending_examples:
            return
        
        print(f"[SelfLearner] Triggering retrain with {len(self.pending_examples)} new examples")
        
        try:
            # Add pending examples to training dataset
            dataset = TrainingDataset()
            for example in self.pending_examples:
                dataset.add_example(example)
            dataset.save()
            
            # Retrain response analyzer
            from core.ml_analysis.response_analyzer import ResponseAnalyzer
            analyzer = ResponseAnalyzer()
            analyzer.train(dataset)
            
            # Update stats
            self.stats.model_version += 1
            self.stats.last_training_time = datetime.now().isoformat()
            
            # Clear pending examples
            with self._lock:
                self.pending_examples.clear()
            
            self.save()
            print(f"[SelfLearner] Retrain complete, model version: {self.stats.model_version}")
            
        except Exception as e:
            print(f"[SelfLearner] Retrain error: {e}")
    
    def get_stats(self) -> Dict:
        """Get learning statistics."""
        return asdict(self.stats)
    
    def get_accuracy_by_type(self) -> Dict[str, float]:
        """Get accuracy breakdown by vulnerability type."""
        result = {}
        for vuln_type, data in self.stats.by_vuln_type.items():
            if data["total"] > 0:
                result[vuln_type] = data["correct_predictions"] / data["total"]
        return result
    
    def get_recent_events(self, limit: int = 50) -> List[Dict]:
        """Get recent learning events."""
        return [asdict(e) for e in self.events[-limit:]]
    
    def should_retrain(self) -> bool:
        """Check if model should be retrained."""
        # Check pending examples threshold
        if len(self.pending_examples) >= self.RETRAIN_THRESHOLD:
            return True
        
        # Check accuracy degradation
        if self.stats.total_events > 100 and self.stats.accuracy < self.MIN_ACCURACY_THRESHOLD:
            return True
        
        return False
    
    def force_retrain(self):
        """Force model retraining."""
        print("[SelfLearner] Forcing retrain...")
        self._trigger_retrain()
    
    def get_improvement_suggestions(self) -> List[str]:
        """Get suggestions for improving model performance."""
        suggestions = []
        
        # Check overall accuracy
        if self.stats.accuracy < 0.7:
            suggestions.append(f"Overall accuracy is low ({self.stats.accuracy:.1%}). Consider adding more training data.")
        
        # Check by vulnerability type
        for vuln_type, data in self.stats.by_vuln_type.items():
            if data["total"] >= 10:
                acc = data["correct_predictions"] / data["total"]
                if acc < 0.6:
                    suggestions.append(f"Low accuracy for {vuln_type} ({acc:.1%}). Add more {vuln_type} training examples.")
        
        # Check class imbalance
        confirmed_count = sum(1 for e in self.events if e.is_confirmed)
        if len(self.events) > 50:
            ratio = confirmed_count / len(self.events)
            if ratio < 0.2:
                suggestions.append("Few confirmed vulnerabilities. Model may be biased toward 'secure'.")
            elif ratio > 0.8:
                suggestions.append("Many confirmed vulnerabilities. Model may be biased toward 'vulnerable'.")
        
        # Check false positives/negatives
        if self.stats.false_positives > self.stats.false_negatives * 3:
            suggestions.append("High false positive rate. Consider adding more secure response examples.")
        elif self.stats.false_negatives > self.stats.false_positives * 3:
            suggestions.append("High false negative rate. Model may be missing vulnerabilities.")
        
        if not suggestions:
            suggestions.append("Model is performing well. Continue collecting training data.")
        
        return suggestions


# =============================================================================
# SINGLETON ACCESS
# =============================================================================

_learner_instance = None
_learner_lock = threading.Lock()

def get_self_learner() -> SelfLearner:
    """Get singleton self-learner instance."""
    global _learner_instance
    with _learner_lock:
        if _learner_instance is None:
            _learner_instance = SelfLearner()
    return _learner_instance


def record_scan_result(
    vuln_type: str,
    endpoint: str,
    param: str,
    payload: str,
    is_confirmed: bool,
    response_status: int,
    response_body: str,
    ml_prediction: str = "",
    ml_confidence: float = 0.0
):
    """
    Convenience function to record a scan result for learning.
    
    Called from executor when a vulnerability test completes.
    """
    learner = get_self_learner()
    learner.record_result(
        vuln_type=vuln_type,
        endpoint=endpoint,
        param=param,
        payload=payload,
        is_confirmed=is_confirmed,
        response_status=response_status,
        response_body=response_body,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence
    )


def get_learning_stats() -> Dict:
    """Get current learning statistics."""
    learner = get_self_learner()
    return learner.get_stats()


def check_and_retrain():
    """Check if retraining is needed and trigger if so."""
    learner = get_self_learner()
    if learner.should_retrain():
        learner.force_retrain()


if __name__ == "__main__":
    # Test the self-learner
    learner = SelfLearner()
    
    # Simulate some scan results
    print("Recording simulated scan results...")
    
    learner.record_result(
        vuln_type="sqli",
        endpoint="http://test.com/login",
        param="username",
        payload="' OR '1'='1",
        is_confirmed=True,
        response_status=200,
        response_body="Welcome admin",
        ml_prediction="sqli",
        ml_confidence=0.85
    )
    
    learner.record_result(
        vuln_type="xss",
        endpoint="http://test.com/search",
        param="q",
        payload="<script>alert(1)</script>",
        is_confirmed=False,
        response_status=200,
        response_body="No results found",
        ml_prediction="xss",
        ml_confidence=0.6
    )
    
    learner.save()
    
    print("\nLearning Stats:")
    stats = learner.get_stats()
    print(f"  Total events: {stats['total_events']}")
    print(f"  Accuracy: {stats['accuracy']:.1%}")
    print(f"  Model version: {stats['model_version']}")
    
    print("\nImprovement Suggestions:")
    for suggestion in learner.get_improvement_suggestions():
        print(f"  - {suggestion}")
