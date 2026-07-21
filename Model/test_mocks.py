"""
Script để chạy thử nghiệm 4 mock json data (SAFE, MEDIUM, HIGH, CRITICAL)
qua 4 model (XGBoost, Decision Tree, Random Forest, Linear Regression).
"""
import os
import pickle
import json
import numpy as np

# Giả lập import từ base_model.py
from base_model import UserPredictorV2, OUTPUT_DIR
import xgboost_model
import decision_tree
import random_forest
import linear_regression

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.normpath(os.path.join(BASE_DIR, "..", ".."))
MOCK_DIR = os.path.join(PROJECT_DIR, "Model Train", "Label", "MockData")

MOCKS = [
    os.path.join(MOCK_DIR, "mock_safe.json"),
    os.path.join(MOCK_DIR, "mock_medium.json"),
    os.path.join(MOCK_DIR, "mock_high.json"),
    os.path.join(MOCK_DIR, "mock_critical.json")
]

MODELS_INFO = [
    ("XGBoost", "xgboost", xgboost_model.XGBoostOOP),
    ("DecisionTree", "decision_tree", decision_tree.DecisionTreeOOP),
    ("RandomForest", "random_forest", random_forest.RandomForestOOP),
    ("LinearRegression", "linear_regression", linear_regression.LinearRegressionOOP),
]

def load_pkl(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def run_tests():
    print("=" * 80)
    print(" BẮT ĐẦU KIỂM TRA MOCK DATA")
    print("=" * 80)
    
    for mock_file in MOCKS:
        with open(mock_file, 'r', encoding='utf-8') as mf:
            cve_id = json.load(mf).get("cve_id")
        
        print(f"\n[{cve_id}] - {os.path.basename(mock_file)}")
        print("-" * 50)
        
        for model_name, prefix, model_class in MODELS_INFO:
            # Load model pkl
            model_path = os.path.join(OUTPUT_DIR, f"{prefix}_model.pkl")
            encoders_path = os.path.join(OUTPUT_DIR, f"{prefix}_encoders.pkl")
            
            if not os.path.exists(model_path) or not os.path.exists(encoders_path):
                print(f"Skipping {model_name}, missing .pkl file")
                continue
                
            model_instance = model_class()
            model_instance.model = load_pkl(model_path)
            
            encoders = load_pkl(encoders_path)
            # Khôi phục lại feature names bằng các keys của encoder hoặc dummy
            # Để đơn giản, ta load lại CSV hoặc set tay feature_names chuẩn
            feature_names = [
                "attack_vector", "attack_complexity", "privileges_required",
                "user_interaction", "scope", "confidentiality", "integrity",
                "availability", "cwe_id_grouped", "base_score", 
                "exploitability_score", "impact_score", "is_cvss3_or_higher",
                "has_valid_cvss", "cwe_is_generic"
            ]
            
            predictor = UserPredictorV2(
                model=model_instance,
                encoders=encoders,
                feature_names=feature_names,
                json_path=mock_file
            )
            
            # Tắt print gốc của UserPredictorV2 để stdout gọn hơn
            import sys, io
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            
            try:
                epss = predictor.predict_user()
            finally:
                sys.stdout = old_stdout
            
            # Predict risk
            if epss >= 0.30: risk = "🔴 RẤT CAO"
            elif epss >= 0.10: risk = "🟠 CAO"
            elif epss >= 0.01: risk = "🟡 TRUNG BÌNH"
            else: risk = "🟢 THẤP"
            
            print(f" {model_name:18} | EPSS: {epss:.6f} | Risk: {risk}")

if __name__ == "__main__":
    run_tests()
