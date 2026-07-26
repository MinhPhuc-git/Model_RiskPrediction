import numpy as np
import json
# pyrefly: ignore [missing-import]
from xgboost import XGBClassifier as XGBoostModel
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score

from base_model import DataLoaderV4, BaseModelOOP, OUTPUT_DIR, PREDICT_DIR, LABELED_JSON
from base_model import Predictor, find_best_threshold, compute_risk_thresholds
import os


class XGBoostOOP(BaseModelOOP):
    def __init__(self, scale_pos_weight: float = 1.0, output_dir: str = OUTPUT_DIR):
        output_dir = os.path.join(output_dir, "xgboost")
        super().__init__(name="xgboost", output_dir=output_dir)
        self.best_iteration_ = None
        self.model = XGBoostModel(
            n_estimators=1200,
            max_depth=8,
            learning_rate=0.02,
            subsample=0.85,
            colsample_bytree=0.85,
            min_child_weight=5,
            gamma=0.1,
            reg_alpha=0.05,
            reg_lambda=1.0,
            objective="binary:logistic",
            eval_metric="aucpr",
            scale_pos_weight=scale_pos_weight * 2,
            early_stopping_rounds=30,
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

    def save_feature_importance(self, feature_names: list) -> str:
        importances = np.array(self.model.feature_importances_, dtype=float)
        total = importances.sum()
        if total > 0:
            normalized = importances / total
        else:
            normalized = importances

        fi_records = [
            {"feature": feat, "importance_weight": round(float(w), 6)}
            for feat, w in sorted(
                zip(feature_names, normalized), key=lambda x: x[1], reverse=True
            )
        ]

        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, f"{self.name}_feature_importance.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(fi_records, f, indent=2, ensure_ascii=False)
        return path


def _run_predict_only(model_path: str, encoder_path: str, metrics_path: str):
    print(f"[SKIP TRAIN] Da tim thay model tai: {model_path}")
    print("[SKIP TRAIN] Bo qua buoc train, load model co san de du doan.")

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    feature_names = metrics.get("feature_names")
    tuned_threshold = metrics.get("tuned_threshold", 0.5)
    risk_thresholds = metrics.get("risk_thresholds")  # None -> Predictor tu fallback ve cutoff cu
    reference_probs = metrics.get("validation_probabilities", []) # Lấy mảng phân phối xác suất

    if not feature_names:
        print("[WARN] xgboost_metrics.json thieu 'feature_names' (co the la file cu, "
              "luu truoc khi co tinh nang nay) -> se train lai tu dau.")
        return False

    if not risk_thresholds:
        print("[WARN] xgboost_metrics.json thieu 'risk_thresholds' (file cu) "
              "-> Risk se dung fallback cutoff co dinh 0.4/0.7/0.9 thay vi percentile.")

    predictor = Predictor(
        model_path=model_path,
        encoder_path=encoder_path,
        feature_names=feature_names,
        threshold=tuned_threshold,
        risk_thresholds=risk_thresholds,
        reference_probs=reference_probs, # Truyền vào để tính Percentile
    )

    if not os.path.isfile(LABELED_JSON):
        print(f"[WARN] Khong tim thay file LABELED_JSON tai: {LABELED_JSON}")
        print("[WARN] Bo qua buoc predict_json() vi thieu file input.")
        return True

    result = predictor.predict_json(LABELED_JSON)
    print(f"[SAVE] ket qua du doan (kem Reasons) luu tai: {result['_saved_path']}")
    return True


def _run_train_and_predict():
    """Train tu dau (data -> model -> tune threshold -> save -> predict)."""
    loader = DataLoaderV4()
    loader.load(test_size=0.3, random_state=42)
    print(f"[DATA] tong dong sau lam sach: {len(loader.X_train) + len(loader.X_test)}")
    print(f"[DATA] features ({len(loader.feature_names)}): {loader.feature_names}")

    X_tr, X_val, y_tr, y_val = train_test_split(
        loader.X_train, loader.y_train,
        test_size=0.2, random_state=42, stratify=loader.y_train,
    )

    spw = loader.scale_pos_weight()
    print(f"[XGBOOST] scale_pos_weight (tinh dong, KHONG nhan them he so) = {spw:.4f}")

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

    val_proba = model.predict_proba(X_val)
    best = find_best_threshold(y_val, val_proba, metric="f1", beta=1.0)
    tuned_threshold = best["threshold"]
    print(f"\n[THRESHOLD] Tune tren validation set -> threshold={tuned_threshold:.4f} "
          f"(val precision={best['precision']:.4f}  val recall={best['recall']:.4f}  "
          f"val f1={best['f1']:.4f})")

    # threshold phân loại rủi ro (RẤT CAO/CAO/TB/THẤP) theo percentile 
    risk_thresholds = compute_risk_thresholds(val_proba, percentiles=(70, 90, 97))
    print(f"[RISK THRESHOLDS] (tinh theo percentile tren validation set)")
    print(f"  medium_threshold   (p{risk_thresholds['percentiles_used']['medium']}) = "
          f"{risk_thresholds['medium_threshold']:.4f}")
    print(f"  high_threshold     (p{risk_thresholds['percentiles_used']['high']}) = "
          f"{risk_thresholds['high_threshold']:.4f}")
    print(f"  critical_threshold (p{risk_thresholds['percentiles_used']['critical']}) = "
          f"{risk_thresholds['critical_threshold']:.4f}")

    # sanity check: ty le CVE roi vao moi nhom tren validation set
    _crit, _high, _med = (risk_thresholds["critical_threshold"],
                           risk_thresholds["high_threshold"], risk_thresholds["medium_threshold"])
    n = len(val_proba)
    n_crit = int((val_proba >= _crit).sum())
    n_high = int(((val_proba >= _high) & (val_proba < _crit)).sum())
    n_med = int(((val_proba >= _med) & (val_proba < _high)).sum())
    n_low = int((val_proba < _med).sum())
    
    print(f"  -> phan bo: RAT CAO={n_crit} ({n_crit/n*100:.1f}%)  CAO={n_high} ({n_high/n*100:.1f}%)  "
          f"TRUNG BINH={n_med} ({n_med/n*100:.1f}%)  THAP={n_low} ({n_low/n*100:.1f}%)")

    print("\n--- Classification Report (threshold=0.5, chi de tham khao) ---")
    print(model.classification_report_str(loader.X_test, loader.y_test, threshold=0.5))

    print(f"--- Classification Report (threshold={tuned_threshold:.4f}, DA TUNE) ---")
    print(model.classification_report_str(loader.X_test, loader.y_test, threshold=tuned_threshold))

    test_at_tuned = model.evaluate_at_threshold(loader.X_test, loader.y_test, threshold=tuned_threshold)
    print(f"[TEST @ tuned threshold] precision={test_at_tuned['precision']:.4f}  "
          f"recall={test_at_tuned['recall']:.4f}  f1={test_at_tuned['f1']:.4f}  "
          f"confusion_matrix={test_at_tuned['confusion_matrix']}")

    metrics["feature_names"] = loader.feature_names  # lưu lại để lần sau load model khỏi train lại
    metrics["tuned_threshold"] = tuned_threshold
    metrics["risk_thresholds"] = risk_thresholds  # lưu lại để lần sau khỏi tính lại
    metrics["validation_probabilities"] = val_proba.tolist() # <--- LƯU LẠI PHÂN PHỐI PERCENTILE
    metrics["val_metrics_at_tuned_threshold"] = {
        "precision": best["precision"], "recall": best["recall"], "f1": best["f1"],
    }
    metrics["test_metrics_at_tuned_threshold"] = test_at_tuned
    metrics["test_metrics_at_threshold_0.5"] = model.evaluate_at_threshold(
        loader.X_test, loader.y_test, threshold=0.5
    )

    # feature importance
    import pandas as pd
    fi = pd.Series(model.model.feature_importances_, index=loader.feature_names).sort_values(ascending=False)
    print("\n--- Feature importance ---")
    print(fi.to_string())

    model.save()
    model.save_encoders(loader.encoders)
    model.save_metrics(metrics)
    fi_path = model.save_feature_importance(loader.feature_names)
    print(f"\n[SAVE] model + encoders + metrics luu tai: {os.path.join(OUTPUT_DIR, 'xgboost')}")
    print(f"[SAVE] feature importance (toan cuc) luu tai: {fi_path}")

    predictor = Predictor(
        model_path=os.path.join(OUTPUT_DIR, "xgboost", "xgboost_model.pkl"),
        encoder_path=os.path.join(OUTPUT_DIR, "xgboost", "xgboost_encoders.pkl"),
        feature_names=loader.feature_names,
        threshold=tuned_threshold,  # dùng threshold đã tune, không còn hardcode 0.5
        risk_thresholds=risk_thresholds,  # RẤT CAO/CAO/TB/THẤP theo percentile
        reference_probs=val_proba.tolist(), # Truyền thẳng phân phối vừa train
    )

    # ── Kiểm tra file JSON input tồn tại trước khi predict (tránh traceback khó hiểu) ──
    if not os.path.isfile(LABELED_JSON):
        print(f"[WARN] Khong tim thay file LABELED_JSON tai: {LABELED_JSON}")
        print("[WARN] Bo qua buoc predict_json() vi thieu file input.")
        return

    # Truyền thẳng LABELED_JSON vào thay vì os.path.join nối chuỗi thủ công
    result = predictor.predict_json(LABELED_JSON)
    print(f"[SAVE] ket qua du doan (kem Reasons) luu tai: {result['_saved_path']}")


def main(force_retrain: bool = False):
    model_dir = os.path.join(OUTPUT_DIR, "xgboost")
    model_path = os.path.join(model_dir, "xgboost_model.pkl")
    encoder_path = os.path.join(model_dir, "xgboost_encoders.pkl")
    metrics_path = os.path.join(model_dir, "xgboost_metrics.json")

    model_exists = (
        os.path.isfile(model_path)
        and os.path.isfile(encoder_path)
        and os.path.isfile(metrics_path)
    )

    if not force_retrain and model_exists:
        handled = _run_predict_only(model_path, encoder_path, metrics_path)
        if handled:
            return
        # handled=False nghia la metrics.json thieu feature_names -> roi xuong train lai

    _run_train_and_predict()


if __name__ == "__main__":
    main()