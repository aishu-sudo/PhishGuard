import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_DIR = r"E:\Project Demo\models\nlp_model"

tokenizer = AutoTokenizer.from_pretrained("xlm-roberta-base")
model     = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
model.eval()

def predict_text(text):
    inputs = tokenizer(text, return_tensors='pt', truncation=True,
                       padding='max_length', max_length=128)
    with torch.no_grad():
        out = model(**inputs)
    probs = torch.softmax(out.logits, dim=1)[0].tolist()
    return {'label': 'PHISHING' if probs[1] >= 0.5 else 'LEGITIMATE',
            'confidence': round(max(probs), 4)}

# Test both languages
print(predict_text("আপনি ৯৯৯ টাকা জিতেছেন: bit.ly/win"))
print(predict_text("Verify your account: http://phish.xyz"))
print(predict_text("Hi, your meeting is at 3pm tomorrow"))