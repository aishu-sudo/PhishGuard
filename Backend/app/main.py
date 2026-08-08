from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import health, analyze
from app.services.correlation.db import init_db

app = FastAPI(title="PhishGuard API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # chrome-extension:// needs this
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(analyze.router)


@app.on_event("startup")
def on_startup():
    init_db()