import os
import json
import warnings
import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score,
    confusion_matrix, classification_report,
    brier_score_loss, log_loss,
    precision_recall_curve,
)
from sklearn.calibration import CalibratedClassifierCV

warnings.filterwarnings("ignore")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Lùi 1 cấp thư mục để về thư mục gốc: AI_CYRP
_PROJECT_DIR = os.path.abspath(os.path.join(_BASE_DIR, ".."))

# Các đường dẫn chuẩn trong dự án
DATA_TRAIN_CSV = os.path.join(_PROJECT_DIR, "Data Train", "350k-Data_HasExploited.csv")
OUTPUT_DIR     = os.path.join(_PROJECT_DIR, "Model Result")
LABELED_JSON   = os.path.join(_PROJECT_DIR, "Label", "agent_data_labeled.json")  # File input
PREDICT_DIR    = os.path.join(_PROJECT_DIR, "Data User")                         # Folder output

TARGET_COL = "Exploited_Label"

# Feature set: CHỈ dùng CVSS_* (không đụng KEV/MS/ExploitDB vì chính là nguồn tạo nhãn)
CATEGORICAL_FEATURES = [
    "CVSS_attack_vector",
    "CVSS_attack_complexity",
    "CVSS_privileges_required",
    "CVSS_user_interaction",
    "CVSS_scope",
    "CVSS_confidentiality",
    "CVSS_integrity",
    "CVSS_availability",
    "CVSS_cvss_version",
]

NUMERICAL_FEATURES = [
    "CVSS_exploitability_score",
    "CVSS_impact_score",
    "CVSS_base_score",
]

BINARY_FEATURES: list[str] = []

_LEAK_PREFIXES = ("KEV_", "MS_", "ExploitDB_")
DROP_EXTRA_COLS = [
    "CVE_ID", "CVSS_cwe_id", "CVSS_vector_string", "CVSS_description",
    "CVSS_published_date", "CVSS_last_modified", "CVSS_earliest_exploit_date",
]


def compute_risk_thresholds(proba, percentiles: tuple = (70, 90, 97)) -> dict:
    p_medium, p_high, p_critical = percentiles
    return {
        "medium_threshold":   float(np.quantile(proba, p_medium / 100.0)),
        "high_threshold":     float(np.quantile(proba, p_high / 100.0)),
        "critical_threshold": float(np.quantile(proba, p_critical / 100.0)),
        "percentiles_used": {"medium": p_medium, "high": p_high, "critical": p_critical},
    }


def classify_risk(prob_exploited: float, thresholds: dict | None = None) -> str:
    """Trả về nhãn rủi ro gọn gàng, không kèm text dài dòng vì đã có percentile tính riêng"""
    if thresholds is None:
        if prob_exploited >= 0.9:
            return "RẤT CAO"
        elif prob_exploited >= 0.7:
            return "CAO"
        elif prob_exploited >= 0.4:
            return "TRUNG BÌNH"
        else:
            return "THẤP"

    critical_t = thresholds["critical_threshold"]
    high_t = thresholds["high_threshold"]
    medium_t = thresholds["medium_threshold"]

    if prob_exploited >= critical_t:
        return "RẤT CAO"
    elif prob_exploited >= high_t:
        return "CAO"
    elif prob_exploited >= medium_t:
        return "TRUNG BÌNH"
    else:
        return "THẤP"


def find_best_threshold(y_true, proba, metric: str = "f1", beta: float = 2.0) -> dict:
    precisions, recalls, thresholds = precision_recall_curve(y_true, proba)
    # precision_recall_curve trả về len(thresholds) = len(precisions) - 1
    b2 = beta ** 2
    f_scores = (1 + b2) * precisions * recalls / (b2 * precisions + recalls + 1e-12)
    best_idx = int(np.argmax(f_scores[:-1])) if len(f_scores) > 1 else 0
    return {
        "threshold": float(thresholds[best_idx]) if len(thresholds) > 0 else 0.5,
        "precision": float(precisions[best_idx]),
        "recall": float(recalls[best_idx]),
        "f1": float(f_scores[best_idx]),
    }


class DataLoaderV4:
    """Load 350k-Data_HasExploited.csv, làm sạch, encode, stratified split."""

    def __init__(self, csv_path: str = DATA_TRAIN_CSV):
        self.csv_path = csv_path
        self.encoders: dict[str, LabelEncoder] = {}
        self.feature_names: list[str] = []
        self.X_train = self.X_test = None
        self.y_train = self.y_test = None

    def load(self, test_size: float = 0.2, random_state: int = 42):
        if not os.path.isfile(self.csv_path):
            raise FileNotFoundError(
                f"[DataLoaderV4] Khong tim thay file train tai:\n  {self.csv_path}\n"
                f"-> Kiem tra lai file 350k-Data_HasExploited.csv da duoc dat dung "
                f"vao thu muc 'Model Train/Data Train/' chua, hoac truyen csv_path "
                f"khac khi khoi tao DataLoaderV4(csv_path=...)."
            )
        df = pd.read_csv(self.csv_path, low_memory=False)

        # ── Drop cột rò rỉ nhãn + cột không dùng ──
        leak_cols = [c for c in df.columns if c.startswith(_LEAK_PREFIXES)]
        df = df.drop(columns=leak_cols + DROP_EXTRA_COLS, errors="ignore")

        # ── Loại bỏ dòng KHÔNG CÓ CVSS hợp lệ (cvss_version == -1, base_score == -1) ──
        df = df[df["CVSS_cvss_version"] != -1]

        # ── Sửa placeholder -1 của CVSS v4 (exploitability/impact_score chưa được tính
        #    cho v4 trong nguồn dữ liệu) thành NaN thật, để XGBoost xử lý missing tự nhiên
        #    thay vì học nhầm -1 như một giá trị số có ý nghĩa ──
        for col in ["CVSS_exploitability_score", "CVSS_impact_score"]:
            df.loc[df[col] == -1, col] = np.nan

        # ── Giữ lại dòng có target hợp lệ ──
        df = df.dropna(subset=[TARGET_COL])

        # ── Encode categorical (fillna bằng 'unknown' trước khi encode) ──
        for col in CATEGORICAL_FEATURES:
            if col in df.columns:
                df[col] = df[col].fillna("unknown").astype(str)
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col])
                self.encoders[col] = le

        all_features = [f for f in CATEGORICAL_FEATURES + NUMERICAL_FEATURES + BINARY_FEATURES
                         if f in df.columns]
        self.feature_names = all_features

        X = df[all_features].values.astype(float)  # NaN numerical giữ nguyên cho XGBoost
        y = df[TARGET_COL].values.astype(int)

        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y,
        )

    def scale_pos_weight(self) -> float:
        """
        n_neg / n_pos tính ĐỘNG trên y_train thực tế (không hardcode).
        LƯU Ý: giá trị trả về đã đủ để bù mất cân bằng lớp — KHÔNG nhân thêm
        bất kỳ hệ số nào nữa ở nơi gọi hàm này (xem TUNING NOTES ở đầu file).
        """
        n_pos = max(int(self.y_train.sum()), 1)
        n_neg = len(self.y_train) - n_pos
        return n_neg / n_pos


class BaseModelOOP:
    def __init__(self, name: str, output_dir: str = OUTPUT_DIR):
        self.name = name
        self.output_dir = output_dir
        self.model = None
        self.calibrated_model = None

    def train(self, X_train, y_train, **kwargs):
        self.model.fit(X_train, y_train)

    def calibrate(self, X_train, y_train, method: str = "isotonic", cv: int = 5):
        self.calibrated_model = CalibratedClassifierCV(self.model, method=method, cv=cv)
        self.calibrated_model.fit(X_train, y_train)
        return self.calibrated_model

    def _active_model(self):
        return self.calibrated_model if self.calibrated_model is not None else self.model

    def predict_proba(self, X) -> np.ndarray:
        proba = self._active_model().predict_proba(X)[:, 1]
        return np.clip(proba, 0.0, 1.0)

    def find_best_threshold(self, X, y, metric: str = "f1", beta: float = 2.0) -> dict:
        """Wrapper tiện dụng: tính proba trên (X, y) rồi tìm threshold tối ưu."""
        proba = self.predict_proba(X)
        return find_best_threshold(y, proba, metric=metric, beta=beta)

    def evaluate(self, X_test, y_test) -> dict:
        proba = self.predict_proba(X_test)
        return {
            "roc_auc":     round(roc_auc_score(y_test, proba), 4),
            "pr_auc":      round(average_precision_score(y_test, proba), 4),
            "brier_score": round(brier_score_loss(y_test, proba), 4),
            "log_loss":    round(log_loss(y_test, proba), 4),
        }

    def evaluate_at_threshold(self, X_test, y_test, threshold: float = 0.5) -> dict:
        proba = self.predict_proba(X_test)
        y_pred = (proba >= threshold).astype(int)
        return {
            "threshold": threshold,
            "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
            "recall":    round(recall_score(y_test, y_pred, zero_division=0), 4),
            "f1":        round(f1_score(y_test, y_pred, zero_division=0), 4),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        }

    def classification_report_str(self, X_test, y_test, threshold: float = 0.5) -> str:
        proba = self.predict_proba(X_test)
        y_pred = (proba >= threshold).astype(int)
        return classification_report(y_test, y_pred, digits=4, zero_division=0)

    def save(self) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, f"{self.name}_model.pkl")
        with open(path, "wb") as f:
            pickle.dump(self._active_model(), f)
        return path

    def save_encoders(self, encoders: dict):
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, f"{self.name}_encoders.pkl")
        with open(path, "wb") as f:
            pickle.dump(encoders, f)
        return path

    def save_metrics(self, metrics: dict):
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, f"{self.name}_metrics.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)
        return path


class Predictor:
    def __init__(self,
                 model_path: str,
                 encoder_path: str,
                 feature_names: list,
                 threshold: float = 0.5,
                 risk_thresholds: dict | None = None,
                 reference_probs: list | None = None):
        with open(model_path, "rb") as f:
            self.model = pickle.load(f)

        with open(encoder_path, "rb") as f:
            self.encoders = pickle.load(f)

        self.feature_names = feature_names
        self.threshold = threshold
        self.risk_thresholds = risk_thresholds
        
        # Lưu phân phối xác suất từ validation để tính percentile
        self.reference_probs = reference_probs or []

    def get_percentile(self, probability: float) -> float:
        if not self.reference_probs:
            return 0.0
        return float((np.array(self.reference_probs) <= probability).mean() * 100)

    def _prepare(self, data: dict):
        row = {
            "CVSS_attack_vector": data["av_label"],
            "CVSS_attack_complexity": data["ac_label"],
            "CVSS_privileges_required": data["pr_label"],
            "CVSS_user_interaction": data["ui_label"],
            "CVSS_scope": data["scope_label"],
            "CVSS_confidentiality": data["c_label"],
            "CVSS_integrity": data["i_label"],
            "CVSS_availability": data["a_label"],
            "CVSS_cvss_version": data["cvss_version"],

            "CVSS_exploitability_score": data["exploitability_score"],
            "CVSS_impact_score": data["impact_score"],
            "CVSS_base_score": data["base_score"]
        }

        # giữ lại giá trị gốc (trước encode) để show trong "reasons"
        raw_values = dict(row)

        for col in CATEGORICAL_FEATURES:
            le = self.encoders[col]
            value = str(row[col])
            if value not in le.classes_:
                value = "unknown"
            row[col] = le.transform([value])[0]

        df = pd.DataFrame([row])
        X = df[self.feature_names].values.astype(float)

        return X, raw_values

    def _get_feature_importance(self) -> dict:
        model = self.model
        importances = None

        # Trường hợp 1: model trực tiếp có feature_importances_ (XGBoost, RF, ...)
        if hasattr(model, "feature_importances_"):
            importances = np.array(model.feature_importances_, dtype=float)

        # Trường hợp 2: model là CalibratedClassifierCV -> lấy các estimator con
        elif hasattr(model, "calibrated_classifiers_"):
            all_imps = []
            for cc in model.calibrated_classifiers_:
                base = getattr(cc, "estimator", None) or getattr(cc, "base_estimator", None)
                if base is not None and hasattr(base, "feature_importances_"):
                    all_imps.append(np.array(base.feature_importances_, dtype=float))
            if all_imps:
                importances = np.mean(all_imps, axis=0)

        if importances is None:
            # Model không hỗ trợ feature_importances_ (vd: SVM, LogisticRegression thường)
            return {}

        if importances.sum() > 0:
            importances = importances / importances.sum()

        return dict(zip(self.feature_names, importances.tolist()))

    def _predict_data(self, data: dict, verbose: bool = True):
        X, raw_values = self._prepare(data)

        probability = float(self.model.predict_proba(X)[0][1])
        prediction = int(probability >= self.threshold)
        
        # ── Tính Percentile và Risk ──
        percentile = self.get_percentile(probability)
        risk = classify_risk(probability, self.risk_thresholds)

        # ── Tính "trọng số nguyên nhân" cho nhãn này ──
        importance_map = self._get_feature_importance()

        reasons = []
        for feat in self.feature_names:
            reasons.append({
                "feature": feat,
                "value": raw_values.get(feat),
                "importance_weight": round(importance_map.get(feat, 0.0), 3),
            })
        # sắp xếp theo trọng số giảm dần -> nguyên nhân ảnh hưởng nhiều nhất lên trên
        reasons.sort(key=lambda r: r["importance_weight"], reverse=True)

        formatted_thresholds = None
        if self.risk_thresholds:
            formatted_thresholds = dict(self.risk_thresholds)
            for k in ["medium_threshold", "high_threshold", "critical_threshold"]:
                if k in formatted_thresholds and isinstance(formatted_thresholds[k], float):
                    formatted_thresholds[k] = round(formatted_thresholds[k], 3)

        result = {
            "CVE_ID": data.get("cve_id", "Unknown"),
            "CWE_ID": data.get("cwe_id", "Unknown"),
            "Probability": round(probability, 4),
            "Percentile": round(percentile, 2) if self.reference_probs else None,
            "Threshold_Used": self.threshold,
            "Prediction": prediction,
            "Risk": risk,
            "Risk_Thresholds_Used": formatted_thresholds,
            "Reasons": reasons,
        }

        if verbose:
            print("\n")
            print(" Prediction Result")
            print("==============================")
            print(f"CVE                : {result['CVE_ID']}")
            print(f"Attack Probability : {probability*100:.2f}%")
            
            # Nếu có đủ dữ liệu percentile thì hiển thị rõ ràng hơn
            if self.reference_probs:
                top_pct = 100.0 - percentile
                print(f"Percentile         : P{percentile:.2f} (Top {top_pct:.2f}%)")
                
            print(f"Decision threshold : {self.threshold:.4f}")
            print(f"Prediction (Exploit): {'EXPLOITED' if prediction else 'NOT EXPLOITED'}")
            print(f"Risk               : {result['Risk']}")
            print("Top nguyên nhân:")
            for r in reasons[:5]:
                print(f"  - {r['feature']} = {r['value']} (weight={r['importance_weight']})")
            print("==============================\n")

        # ── Lưu kết quả + reasons ra JSON trong PREDICT_DIR ──
        os.makedirs(PREDICT_DIR, exist_ok=True)
        out_path = os.path.join(PREDICT_DIR, f"{result['CVE_ID']}_result.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        result["_saved_path"] = out_path
        return result

    def predict_json(self, json_path: str, verbose: bool = True):
        with open(json_path, "r", encoding="utf8") as f:
            data = json.load(f)
        return self._predict_data(data, verbose=verbose)

    def predict_extracted_row(self, row: dict, verbose: bool = True):
        data = {}
        data["cve_id"] = row.get("cve_id", "")
        data["cwe_id"] = row.get("cwe_id", "Unknown")
        
        # Uu tien v3, fallback v2
        data["av_label"] = row.get("cvss_v3_attack_vector") or row.get("cvss_v2_access_vector") or "unknown"
        data["ac_label"] = row.get("cvss_v3_attack_complexity") or row.get("cvss_v2_access_complexity") or "unknown"
        data["pr_label"] = row.get("cvss_v3_privileges_required") or row.get("cvss_v2_authentication") or "unknown"
        data["ui_label"] = row.get("cvss_v3_user_interaction") or "unknown"
        data["scope_label"] = row.get("cvss_v3_scope") or "unknown"
        data["c_label"] = row.get("cvss_v3_confidentiality_impact") or row.get("cvss_v2_confidentiality_impact") or "unknown"
        data["i_label"] = row.get("cvss_v3_integrity_impact") or row.get("cvss_v2_integrity_impact") or "unknown"
        data["a_label"] = row.get("cvss_v3_availability_impact") or row.get("cvss_v2_availability_impact") or "unknown"
        data["cvss_version"] = row.get("cvss_final_version") or "unknown"
        
        def to_float(val, default=0.0):
            try:
                if val == "" or val is None: return default
                return float(val)
            except:
                return default

        data["exploitability_score"] = to_float(row.get("cvss_final_exploitability_subscore"))
        data["impact_score"] = to_float(row.get("cvss_final_impact_subscore"))
        data["base_score"] = to_float(row.get("cvss_final_score"))

        return self._predict_data(data, verbose=verbose)