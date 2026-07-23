"""
Base module cho model dự đoán "khả năng bị khai thác" (exploited).
Retuned cho Main_Data_Train.csv (86,052 dòng, schema mới KEV/MS/ExploitDB/CVSS).

Nhãn: `Exploited_Label` = OR(KEV_Listed_Flag, MS_Exploited_Flag, ExploitDB_Verified_Flag)
  -> mọi cột KEV_*/MS_*/ExploitDB_* RÒ RỈ NHÃN TUYỆT ĐỐI, không được dùng làm feature.
  -> Chỉ dùng các cột CVSS_* (độc lập với cách gán nhãn) làm feature.

Mất cân bằng thực tế: 75% (0) / 25% (1) -- KHÁC với giả định cũ (93.86/6.14).
scale_pos_weight phải tính động từ y_train, không hardcode.
"""
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
)
from sklearn.calibration import CalibratedClassifierCV

warnings.filterwarnings("ignore")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Lùi 2 cấp thư mục để về thư mục gốc: .../Agent-CollectionData
_PROJECT_DIR = os.path.abspath(os.path.join(_BASE_DIR, "..", ".."))

# Trỏ chính xác vào thư mục Model Train ở gốc dự án
import os

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Lùi 2 cấp thư mục để về thư mục gốc: .../Agent-CollectionData
_PROJECT_DIR = os.path.abspath(os.path.join(_BASE_DIR, "..", ".."))

# Các đường dẫn chuẩn trong dự án
DATA_TRAIN_CSV = os.path.join(_PROJECT_DIR, "Model Train", "Data Train", "Full_CVE_Dataset_with_Exploited_Label.csv")
OUTPUT_DIR     = os.path.join(_PROJECT_DIR, "Model Train", "Model Result")
LABELED_JSON   = os.path.join(_PROJECT_DIR, "Model Train", "Label", "agent_data_labeled.json")  # File input
PREDICT_DIR    = os.path.join(_PROJECT_DIR, "Model Train", "Data User")                         # Folder output

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


def classify_risk(prob_exploited: float) -> str:
    if prob_exploited >= 0.9:
        return "RẤT CAO (>= 90%)"
    elif prob_exploited >= 0.7:
        return "CAO (70-89%)"
    elif prob_exploited >= 0.4:
        return "TRUNG BÌNH (40-69%)"
    else:
        return "THẤP (< 40%)"


class DataLoaderV4:
    """Load Main_Data_Train.csv, làm sạch, encode, stratified split."""

    def __init__(self, csv_path: str = DATA_TRAIN_CSV):
        self.csv_path = csv_path
        self.encoders: dict[str, LabelEncoder] = {}
        self.feature_names: list[str] = []
        self.X_train = self.X_test = None
        self.y_train = self.y_test = None

    def load(self, test_size: float = 0.2, random_state: int = 42):
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
        """n_neg / n_pos tính ĐỘNG trên y_train thực tế (không hardcode)."""
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
                 feature_names: list):

        with open(model_path, "rb") as f:
            self.model = pickle.load(f)

        with open(encoder_path, "rb") as f:
            self.encoders = pickle.load(f)

        self.feature_names = feature_names

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

        for col in CATEGORICAL_FEATURES:
            le = self.encoders[col]
            value = str(row[col])
            if value not in le.classes_:
                value = "unknown"
            row[col] = le.transform([value])[0]

        df = pd.DataFrame([row])
        X = df[self.feature_names].values.astype(float)

        return X

    def predict_json(self, json_path: str):

        with open(json_path, "r", encoding="utf8") as f:
            data = json.load(f)

        X = self._prepare(data)

        probability = float(self.model.predict_proba(X)[0][1])

        prediction = int(probability >= 0.5)

        result = {
            "CVE_ID": data["cve_id"],
            "Probability": round(probability, 4),
            "Prediction": prediction,
            "Risk": classify_risk(probability)
        }

        print("\n")
        print(" Prediction Result")
        print("==============================")
        print("CVE :", result["CVE_ID"])
        print("Attack Probability :", f"{probability*100:.2f}%")
        print("Prediction (Exploit):", "EXPLOITED" if prediction else "NOT EXPLOITED")
        print("Risk :", result["Risk"])
        print("==============================\n")

        return result