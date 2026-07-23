import os

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))          # Sever/Model
SEVER_DIR   = os.path.dirname(BASE_DIR)                           # Sever
PROJECT_DIR = os.path.dirname(SEVER_DIR)                          # AGENT-COLLECTIONDATA

# ── Dataset paths ──
CSV_PATH = os.path.join(PROJECT_DIR, "Model Train", "Data Train" , "Main_Data_Train.csv")
AGENT_JSON_PATH = os.path.join(PROJECT_DIR, "Model Train", "Label", "agent_data_labeled.json")

# ── Model result directory ──
MODEL_RESULT_DIR = os.path.join(PROJECT_DIR, "Model Train", "Model Result")
os.makedirs(MODEL_RESULT_DIR, exist_ok=True)

# ── Trained model files ──
DECISION_TREE_MODEL       = os.path.join(MODEL_RESULT_DIR, "decision_tree_model.pkl")
RANDOM_FOREST_MODEL       = os.path.join(MODEL_RESULT_DIR, "random_forest_model.pkl")
LINEAR_REGRESSION_MODEL   = os.path.join(MODEL_RESULT_DIR, "linear_regression_model.pkl")
XGBOOST_MODEL             = os.path.join(MODEL_RESULT_DIR, "xgboost_model.json")

# ── Encoder files ──
DECISION_TREE_ENCODERS    = os.path.join(MODEL_RESULT_DIR, "decision_tree_encoders.pkl")
RANDOM_FOREST_ENCODERS    = os.path.join(MODEL_RESULT_DIR, "random_forest_encoders.pkl")
LINEAR_REGRESSION_ENCODERS = os.path.join(MODEL_RESULT_DIR, "linear_regression_encoders.pkl")
XGBOOST_ENCODERS          = os.path.join(MODEL_RESULT_DIR, "xgboost_encoders.pkl")
LABEL_ENCODER             = os.path.join(MODEL_RESULT_DIR, "label_encoders.pkl")