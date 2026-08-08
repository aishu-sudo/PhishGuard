from pathlib import Path
from app.config import NLP_MODEL_DIR

_tokenizer = None
_model = None

def _get_nlp_model():
    global _tokenizer, _model
    if _tokenizer is None or _model is None:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        model_path = str(NLP_MODEL_DIR) if Path(NLP_MODEL_DIR).exists() else "aishuzaman/phishguard-nlp-v2"
        print(f"[nlp] Loading model from {model_path}...")
        _tokenizer = AutoTokenizer.from_pretrained(model_path)
        _model     = AutoModelForSequenceClassification.from_pretrained(model_path)
        _model.eval()
        print(f"[nlp] Model loaded successfully.")
    return _tokenizer, _model

def classify_text(text: str, threshold: float = 0.5) -> dict:
    import torch
    tokenizer, model = _get_nlp_model()
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding="max_length",
        max_length=128,
    )
    with torch.no_grad():
        logits = model(**inputs).logits

    probs        = torch.softmax(logits, dim=1)[0].tolist()
    phish_prob   = probs[1]
    label        = "PHISHING" if phish_prob >= threshold else "LEGITIMATE"

    return {
        "label":       label,
        "confidence":  round(max(probs), 4),
        "phishing_probability":   round(phish_prob, 4),
        "legitimate_probability": round(probs[0],   4),
    }
