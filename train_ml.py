from core.ml_analysis.data_processing import DatasetBuilder
from core.ml_analysis.classifier import BinaryVulnerabilityClassifier
from core.ml_analysis.predictor import VulnerabilityPredictor
from sklearn.model_selection import train_test_split
import pandas as pd
import warnings

warnings.filterwarnings('ignore')

def run_training_pipeline():
    """Complete training pipeline"""
    print("[*] STARTING TRAINING PIPELINE")
    print("="*60)
    
    # Step 1: Build dataset
    builder = DatasetBuilder()
    df = builder.build_dataset(num_cves=200)
    
    # Step 2: Prepare features
    X, y, vectorizer = builder.prepare_features(df)
    
    # Step 3: Split data
    # FIX T1: Fall back to non-stratified split if any class has < 2 samples
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
    except ValueError:
        print("[!] Warning: Stratified split failed (rare class). Using random split instead.")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
    
    print(f"\n[*] Data Split:")
    print(f"   Training samples: {len(X_train)}")
    print(f"   Testing samples:  {len(X_test)}")
    
    # Step 4: Train classifier
    classifier = BinaryVulnerabilityClassifier()
    classifier.vectorizer = vectorizer
    classifier.train(X_train, y_train)
    
    # Step 5: Evaluate
    classifier.evaluate(X_test, y_test)
    
    # Step 6: Save model
    classifier.save_model("data/vuln_classifier.pkl", "data/vectorizer.pkl")
    
    return classifier, df

if __name__ == "__main__":
    try:
        run_training_pipeline()
    except Exception as e:
        print(f"[-] Error during training: {e}")
