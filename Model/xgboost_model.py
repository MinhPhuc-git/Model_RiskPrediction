import numpy as np
# pyrefly: ignore [missing-import]
from xgboost import XGBClassifier as XGBoostModel
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score

from base_model import DataLoaderV4, BaseModelOOP, OUTPUT_DIR, PREDICT_DIR, LABELED_JSON
from base_model import Predictor
import os
class XGBoostOOP(BaseModelOOP):
    def __init__(self, scale_pos_weight: float = 1.0, output_dir: str = OUTPUT_DIR):
        output_dir = os.path.join(output_dir, "xgboost")
        super().__init__(name="xgboost", output_dir=output_dir)
        self.best_iteration_ = None
        self.model = XGBoostModel(
            n_estimators=1000,
            max_depth=12, 
            learning_rate=0.04,
            subsample=0.9,
            colsample_bytree=0.9,
            min_child_weight=1,
            gamma=0.0,
            reg_alpha=0.0,
            reg_lambda=0.1,
            objective="binary:logistic",
            eval_metric="aucpr",
            scale_pos_weight=scale_pos_weight * 15.0,
            early_stopping_rounds=99,
            random_state=42,
            verbosity=0,
            n_jobs=-1,
        )

    def train(self, X_train, y_train, X_val=None, y_val=None):
        if X_val is not None and y_val is not None:
            self.model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
            best_n = self.model.best_iteration + 1
            self.best_iteration_ = best_n
            print(f"[XGBOOST] early stopping tai {best_n} cay (tong {self.model.n_estimators})")
            self.model.set_params(n_estimators=best_n, early_stopping_rounds=None)
        else:
            self.model.set_params(early_stopping_rounds=None)

        self.model.fit(X_train, y_train)

    def save(self) -> str:
        path = super().save()
        json_path = path.replace(".pkl", ".json")
        self.model.save_model(json_path)
        return path


def main():
    loader = DataLoaderV4()
    loader.load(test_size=0.3, random_state=42)
    print(f"[DATA] tong dong sau lam sach: {len(loader.X_train) + len(loader.X_test)}")
    print(f"[DATA] features ({len(loader.feature_names)}): {loader.feature_names}")

    X_tr, X_val, y_tr, y_val = train_test_split(
        loader.X_train, loader.y_train,
        test_size=0.2, random_state=42, stratify=loader.y_train,
    )

    spw = loader.scale_pos_weight()
    print(f"[XGBOOST] scale_pos_weight (tinh dong) = {spw:.4f}")

    model = XGBoostOOP(scale_pos_weight=spw)
    model.train(X_tr, y_tr, X_val=X_val, y_val=y_val)
    print(f"[XGBOOST] best_iteration = {model.best_iteration_}")

    proba_train = model.model.predict_proba(X_tr)[:, 1]
    proba_test_raw = model.model.predict_proba(loader.X_test)[:, 1]
    auc_tr = roc_auc_score(y_tr, proba_train)
    auc_te = roc_auc_score(loader.y_test, proba_test_raw)
    print(f"[XGBOOST] Train ROC-AUC={auc_tr:.4f}  Test ROC-AUC={auc_te:.4f}  Gap={auc_tr - auc_te:.4f}")

    metrics = model.evaluate(loader.X_test, loader.y_test)
    print(f"[XGBOOST] ROC-AUC={metrics['roc_auc']:.4f}  PR-AUC={metrics['pr_auc']:.4f}  "
          f"Brier={metrics['brier_score']:.4f}  LogLoss={metrics['log_loss']:.4f}")

    print("\n--- Classification Report (threshold=0.5) ---")
    print(model.classification_report_str(loader.X_test, loader.y_test, threshold=0.5))

    # feature importance
    import pandas as pd
    fi = pd.Series(model.model.feature_importances_, index=loader.feature_names).sort_values(ascending=False)
    print("\n--- Feature importance ---")
    print(fi.to_string())

    model.save()
    model.save_encoders(loader.encoders)
    model.save_metrics(metrics)
    print(f"\n[SAVE] model + encoders + metrics luu tai: {os.path.join(OUTPUT_DIR, 'xgboost')}")

    predictor = Predictor(
        model_path=os.path.join(OUTPUT_DIR, "xgboost", "xgboost_model.pkl"),
        encoder_path=os.path.join(OUTPUT_DIR, "xgboost", "xgboost_encoders.pkl"),
        feature_names=loader.feature_names
    )

    # Truyền thẳng LABELED_JSON vào thay vì os.path.join nối chuỗi thủ công
    predictor.predict_json(LABELED_JSON)

if __name__ == "__main__":
    main()