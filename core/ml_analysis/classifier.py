from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# B-14 FIX: Use absolute path anchored to this file's location (not cwd-relative)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = _PROJECT_ROOT / "data" / "ml_models"

class BinaryVulnerabilityClassifier:
    """Binary classifier for vulnerability detection"""
    
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            class_weight='balanced',
            random_state=42
        )
        self.vectorizer = None
        self.is_trained = False
        
    def train(self, X_train, y_train, vectorizer=None):
        """Train the model. Pass the fitted vectorizer so it can be persisted."""
        print("[*] Training classifier...")
        self.model.fit(X_train, y_train)
        self.is_trained = True
        # B-03 FIX: Store vectorizer so save_model() serialises a real object
        if vectorizer is not None:
            self.vectorizer = vectorizer
        print("[+] Model training complete!")
        return self.model
    
    def predict(self, X):
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        return predictions, probabilities
    
    def evaluate(self, X_test, y_test):
        print("[*] Evaluating model...")
        predictions, probabilities = self.predict(X_test)
        
        print("\n" + "="*50)
        print("CLASSIFICATION REPORT")
        print("="*50)
        print(classification_report(y_test, predictions, target_names=['Secure', 'Vulnerable']))
        
        cm = confusion_matrix(y_test, predictions)
        print("\nCONFUSION MATRIX:")
        print(f"True Negatives:  {cm[0,0]}")
        print(f"False Positives: {cm[0,1]}")
        print(f"False Negatives: {cm[1,0]}")
        print(f"True Positives:  {cm[1,1]}")
        
    def save_model(self, model_path=None, vectorizer_path=None):
        # B-14 FIX: Fall back to absolute paths so models are found regardless of cwd
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        if model_path is None:
            model_path = MODEL_DIR / "vuln_classifier.pkl"
        if vectorizer_path is None:
            vectorizer_path = MODEL_DIR / "vectorizer.pkl"
        # B-03 FIX: Only save vectorizer when it is not None
        if self.vectorizer is None:
            print("[!] Warning: vectorizer is None — skipping vectorizer save. "
                  "Call train(X, y, vectorizer=vec) to persist the vectorizer.")
        else:
            joblib.dump(self.vectorizer, vectorizer_path)
            print(f"[+] Vectorizer saved to {vectorizer_path}")
        joblib.dump(self.model, model_path)
        print(f"[+] Model saved to {model_path}")
    
    def load_model(self, model_path=None, vectorizer_path=None):
        if model_path is None:
            model_path = MODEL_DIR / "vuln_classifier.pkl"
        if vectorizer_path is None:
            vectorizer_path = MODEL_DIR / "vectorizer.pkl"
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        self.is_trained = True
        print(f"[*] Model loaded from {model_path}")
