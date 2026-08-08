import os
from pathlib import Path
from dotenv import load_dotenv
import joblib

load_dotenv(Path(__file__).parent.parent / ".env")

BASE_DIR      = Path(__file__).parent.parent.parent

_models_env = os.getenv("MODELS_DIR")
_nlp_env    = os.getenv("NLP_MODEL_DIR")

MODELS_DIR    = (BASE_DIR / _models_env).resolve() if _models_env else (BASE_DIR / "Research/models").resolve()
NLP_MODEL_DIR = (BASE_DIR / _nlp_env).resolve() if _nlp_env else (BASE_DIR / "Research/models/nlp_model").resolve()

print(f"[config] BASE_DIR resolved to: {BASE_DIR}")
print(f"[config] MODELS_DIR resolved to: {MODELS_DIR}")

# URL model files
XGB_MODEL_PATH      = MODELS_DIR / "xgboost_url_model.pkl"
ISO_MODEL_PATH      = MODELS_DIR / "isolation_forest_url_model.pkl"
TFIDF_PATH          = MODELS_DIR / "tfidf_vectorizer.pkl"
FEATURE_NAMES_PATH  = MODELS_DIR / "url_feature_names.pkl"
URL_META_PATH       = MODELS_DIR / "url_meta.pkl"


W_SUPERVISED     = 0.70
W_ANOMALY        = 0.30
ANOMALY_MIN      = 0.40
ANOMALY_MAX      = 0.70
RED_THRESHOLD    = 0.65
YELLOW_THRESHOLD = 0.40
SAFE_BROWSING_BONUS = 0.25

try:
    _meta = joblib.load(URL_META_PATH)
    W_SUPERVISED     = float(_meta.get("w_supervised", W_SUPERVISED))
    W_ANOMALY        = float(_meta.get("w_anomaly", W_ANOMALY))
    ANOMALY_MIN      = float(_meta.get("anomaly_min", ANOMALY_MIN))
    ANOMALY_MAX      = float(_meta.get("anomaly_max", ANOMALY_MAX))
    RED_THRESHOLD    = float(_meta.get("red_threshold", RED_THRESHOLD))
    YELLOW_THRESHOLD = float(_meta.get("yellow_threshold", YELLOW_THRESHOLD))
    SAFE_BROWSING_BONUS = 0.25
    print(f"[config] Calibration loaded from url_meta.pkl -> "
          f"RED>={RED_THRESHOLD:.3f}  YELLOW>={YELLOW_THRESHOLD:.3f}  "
          f"anomaly[{ANOMALY_MIN:.3f},{ANOMALY_MAX:.3f}]")
except Exception as e:
    print(f"[config] url_meta.pkl not loaded ({e}); using fallback thresholds")

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
VT_AUTO_SUBMIT = os.getenv("VT_AUTO_SUBMIT", "true").lower() == "true"