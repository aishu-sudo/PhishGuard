from pathlib import Path
from app.config import NLP_MODEL_DIR

_tokenizer = None
_model = None

def classify_text(text: str, threshold: float = 0.5) -> dict:
    global _tokenizer, _model

    # Try HuggingFace PyTorch Transformer model first
    try:
        if _tokenizer is None or _model is None:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            model_path = str(NLP_MODEL_DIR) if Path(NLP_MODEL_DIR).exists() else "aishuzaman/phishguard-nlp-v2"
            print(f"[nlp] Loading model from {model_path}...")
            _tokenizer = AutoTokenizer.from_pretrained(model_path)
            _model     = AutoModelForSequenceClassification.from_pretrained(model_path)
            _model.eval()
            print(f"[nlp] Model loaded successfully.")

        import torch
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
    except Exception as e:
        print(f"[nlp] Transformer fallback engaged ({e})")
        phish_keywords = [
            "verify", "urgent", "suspended", "account", "password", 
            "security", "bank", "login", "confirm", "click", "update",
            "wallet", "crypto", "unauthorized", "immediately", "action required",
            "claim", "prize", "winner", "ssn", "credit card", "access"
        ]
        text_lower = text.lower()
        matched = [w for w in phish_keywords if w in text_lower]

        if matched:
            phish_prob = min(0.98, 0.40 + len(matched) * 0.15)
        else:
            phish_prob = 0.02

        label = "PHISHING" if phish_prob >= threshold else "LEGITIMATE"
        conf = phish_prob if label == "PHISHING" else round(1.0 - phish_prob, 4)

        return {
            "label": label,
            "confidence": round(conf, 4),
            "phishing_probability": round(phish_prob, 4),
            "legitimate_probability": round(1.0 - phish_prob, 4),
            "note": "intent_heuristic_engine"
        }
