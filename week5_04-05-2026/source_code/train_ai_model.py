import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import os
from sklearn.linear_model import LogisticRegression
import warnings

warnings.filterwarnings("ignore")

print("[*] Starting AI Training Process...")

# ==========================================
# DATA LOADING
# ==========================================
def load_unified_dataset(filepath):
    print(f"[*] Loading and processing dataset from: {filepath}\n")
    if not os.path.exists(filepath):
        print(f"[!] Error: File '{filepath}' not found!")
        return None, None

    features = []
    labels = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                # Expected format: label, length, entropy, digit_ratio, type_weight, consonant_ratio
                if len(parts) == 6:
                    labels.append(int(parts[0]))
                    features.append([
                        float(parts[1]), float(parts[2]), float(parts[3]), 
                        float(parts[4]), float(parts[5])
                    ])
        return np.array(features), np.array(labels)
    except Exception as e:
        print(f"[!] Error reading dataset: {e}")
        return None, None

# ==========================================
# TRAINING FACTORY
# ==========================================
def train_and_export(X, y):
    print("[*] ================= DATA SPLITTING =================")
    print(f"[*] Total processed samples: {len(X)}")

    # Check for empty dataset before splitting
    if len(X) == 0:
        print("[!] Error: Dataset is empty. Cannot train model.")
        return

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"[*] Training set: {len(X_train)} samples.")
    print(f"[*] Testing set: {len(X_test)} samples.\n")

    # ------------------------------------------
    # 1. DECISION TREE (ID3) -
    # ------------------------------------------
    print("[*] ================= 1. AI TRAINING (Decision Tree / ID3) =================")
    dt_model = DecisionTreeClassifier(criterion='entropy', random_state=42)
    dt_model.fit(X_train, y_train)

    dt_predictions = dt_model.predict(X_test)
    print(f"[+] Accuracy on Test set: {accuracy_score(y_test, dt_predictions) * 100:.2f}%")
    print(f"[+] Confusion Matrix:\n{confusion_matrix(y_test, dt_predictions)}")
    print(f"\n[+] Classification Report:\n{classification_report(y_test, dt_predictions)}")

    # ------------------------------------------
    # 2. RANDOM FOREST
    # ------------------------------------------
    print("\n[*] ================= 2. AI TRAINING (Random Forest) =================")
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=None, oob_score=True, random_state=42)
    rf_model.fit(X_train, y_train)

    print(f"[+] OOB Score: {rf_model.oob_score_ * 100:.2f}%")
    rf_predictions = rf_model.predict(X_test)
    print(f"[+] Accuracy on Test set: {accuracy_score(y_test, rf_predictions) * 100:.2f}%")
    print(f"[+] Confusion Matrix:\n{confusion_matrix(y_test, rf_predictions)}")

    # Classification report for Random Forest
    print(f"\n[+] Classification Report:\n{classification_report(y_test, rf_predictions)}")
    print("\n[+] Feature Importance (Random Forest):")
    # Update feature names for 5D vector
    feature_names = ['Subdomain Length', 'Entropy', 'Digit Ratio', 'Record Type Weight', 'Consonant Ratio']
    importances = rf_model.feature_importances_
    for name, importance in zip(feature_names, importances):
        print(f"    - {name}: {importance * 100:.2f}%")

    # ==========================================
    # 3. AI TRAINING (Logistic Regression - For Research Comparison)
    # ==========================================
    print("\n[*] ================= 3. EXPERIMENTAL: Logistic Regression ================= [*]")
    print("[*] Training Logistic Regression model to evaluate Extrapolation capabilities...")
    
    # max_iter=1000 ensures the math converges properly
    lr_model = LogisticRegression(max_iter=1000, random_state=42)
    lr_model.fit(X_train, y_train)
    
    y_pred_lr = lr_model.predict(X_test)
    acc_lr = accuracy_score(y_test, y_pred_lr)
    
    print(f"[+] Accuracy on Test set: {acc_lr * 100:.2f}%")
    print("[+] Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred_lr))
    print("\n[+] Classification Report:")
    print(classification_report(y_test, y_pred_lr))
    
    # Print coefficients to understand feature importance in Logistic Regression
    print("[+] Learned Feature Weights (Coefficients):")
    coefficients = lr_model.coef_[0]
    for name, weight in zip(feature_names, coefficients):
        print(f"    - {name}: {weight:.4f} (Positive = Higher chance of Malware)")


    # ------------------------------------------
    # EXPORTING
    # ------------------------------------------
    print("\n[*] ================= PACKAGING AI MODEL =================")
    print("[*] Pickling the Decision Tree model for production...")
    with open('ai_model_id3.pkl', 'wb') as f:
        pickle.dump(dt_model, f)
    print("[+] COMPLETED! File 'ai_model_id3.pkl' is ready for Gateway deployment.")

if __name__ == "__main__":
    dataset_file = "cic_unified_features.txt"
    X, y = load_unified_dataset(dataset_file)
    if X is not None and y is not None:
        train_and_export(X, y)