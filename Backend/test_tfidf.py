import joblib
from app.config import TFIDF_PATH

print("Loading:", TFIDF_PATH)

tfidf = joblib.load(TFIDF_PATH)

print("Type:", type(tfidf))
print("Has vocabulary:", hasattr(tfidf, "vocabulary_"))
print("Has idf:", hasattr(tfidf, "idf_"))

try:
    X = tfidf.transform(["google.com"])
    print("Transform successful")
    print("Shape:", X.shape)
except Exception as e:
    print("ERROR:", e)