from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.fusion.decision_fusion import score_url
from app.services.nlp.classifier import classify_text
from app.services.threat_intel import investigate

router = APIRouter()

class URLRequest(BaseModel):
    url: str

class TextRequest(BaseModel):
    text: str

@router.post("/predict/url")
def predict_url(req: URLRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    return score_url(req.url.strip())

@router.post("/predict/fast")
def predict_fast(req: URLRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    return score_url(req.url.strip(), fast=True)

@router.post("/predict/text")
def predict_text(req: TextRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    return classify_text(req.text.strip())

@router.post("/investigate")
def investigate_url(req: URLRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    return investigate(req.url.strip())