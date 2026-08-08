from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from app.config import NLP_MODEL_DIR

_model_path = str(NLP_MODEL_DIR) if Path(NLP_MODEL_DIR).exists() else "aishuzaman/phishguard-nlp-v2"

_tokenizer = AutoTokenizer.from_pretrained(_model_path)
_model     = AutoModelForSequenceClassification.from_pretrained(_model_path)
_model.eval()

print(f"[nlp] Model loaded from {_model_path}")

def classify_text(text: str, threshold: float = 0.5) -> dict:
    inputs = _tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding="max_length",
        max_length=128,
    )
    with torch.no_grad():
        logits = _model(**inputs).logits

    probs        = torch.softmax(logits, dim=1)[0].tolist()
    phish_prob   = probs[1]
    label        = "PHISHING" if phish_prob >= threshold else "LEGITIMATE"

    return {
        "label":       label,
        "confidence":  round(max(probs), 4),
        "phishing_probability":   round(phish_prob, 4),
        "legitimate_probability": round(probs[0],   4),
    }
