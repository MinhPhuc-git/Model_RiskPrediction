"""
Random Forest cho dự đoán exploited=0/1 -- retuned cho Main_Data_Train.csv thực tế.
"""
import numpy as np
from sklearn.ensemble import RandomForestClassifier as RandomForestModel
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score

from base_model import DataLoaderV4, BaseModelOOP, OUTPUT_DIR, LABELED_JSON
from base_model import Predictor
import os

class RandomForestOOP(BaseModelOOP):
    def __init__(self, output_dir: str = OUTPUT_DIR):
        output_dir = os.path.join(output_dir, "random_forest")
        super().__init__(name="random_forest", output_dir=output_dir)
        self.model = RandomForestModel(
            n_estimators=300,
            max_depth= 30,
            min_samples_split=10,
            min_samples_leaf=5,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )

    def train(self, X_train, y_train, X_val=None, y_val=None):
        self.model.fit(X_train, y_train)

def main():
    loader = DataLoaderV4()
    loader.load(test_size=0.2, random_state=42)
    print(f"[DATA] tong dong sau lam sach: {len(loader.X_train) + len(loader.X_test)}")
    print(f"[DATA] features ({len(loader.feature_names)}): {loader.feature_names}")

    X_tr, X_val, y_tr, y_val = train_test_split(
        loader.X_train, loader.y_train,
        test_size=0.15, random_state=42, stratify=loader.y_train,
    )

    model = RandomForestOOP()
    model.train(X_tr, y_tr, X_val=X_val, y_val=y_val)

    proba_train = model.predict_proba(X_tr)
    proba_test_raw = model.predict_proba(loader.X_test)
    auc_tr = roc_auc_score(y_tr, proba_train)
    auc_te = roc_auc_score(loader.y_test, proba_test_raw)
    print(f"[RANDOM FOREST] Train ROC-AUC={auc_tr:.4f}  Test ROC-AUC={auc_te:.4f}  Gap={auc_tr - auc_te:.4f}")

    metrics = model.evaluate(loader.X_test, loader.y_test)
    print(f"[RANDOM FOREST] ROC-AUC={metrics['roc_auc']:.4f}  PR-AUC={metrics['pr_auc']:.4f}  "
          f"Brier={metrics['brier_score']:.4f}  LogLoss={metrics['log_loss']:.4f}")

    print("\n--- Classification Report (threshold=0.5) ---")
    print(model.classification_report_str(loader.X_test, loader.y_test, threshold=0.7))

    # feature importance
    import pandas as pd
    fi = pd.Series(model.model.feature_importances_, index=loader.feature_names).sort_values(ascending=False)
    print("\n--- Feature importance ---")
    print(fi.to_string())

    model.save()
    model.save_encoders(loader.encoders)
    model.save_metrics(metrics)
    print(f"\n[SAVE] model + encoders + metrics luu tai: {os.path.join(OUTPUT_DIR, 'random_forest')}")

    predictor = Predictor(
        model_path=os.path.join(OUTPUT_DIR, "random_forest", "random_forest_model.pkl"),
        encoder_path=os.path.join(OUTPUT_DIR, "random_forest", "random_forest_encoders.pkl"),
        feature_names=loader.feature_names
    )
    predictor.predict_json(LABELED_JSON)

if __name__ == "__main__":
    main()
