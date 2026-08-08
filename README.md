# 🛡️ PhishGuard - AI-Powered Phishing Detection & Intelligence

PhishGuard is an enterprise-grade, multi-model AI system that detects phishing websites and social engineering content in real time.

## 🚀 Live Cloud Services

* **🌐 Frontend Web Portal**: **[https://phish-guard-uipa.vercel.app/](https://phish-guard-uipa.vercel.app/)**
* **⚡ Backend API**: **[https://phishguard-rl19.onrender.com/](https://phishguard-rl19.onrender.com/)**
* **🤖 Transformer Model**: **[aishuzaman/phishguard-nlp-v2](https://huggingface.co/aishuzaman/phishguard-nlp-v2)**

---

## 🏗️ Architecture

```
                               +-------------------------------------+
                               |   PhishGuard Web Portal (Vercel)    |
                               | https://phish-guard-uipa.vercel.app |
                               +------------------+------------------+
                                                  |
                                                  v
+-----------------------+              +---------------------+              +-----------------------+
|  Chrome Extension     | ------------>|  FastAPI Backend    |<------------ |   REST / API Clients  |
|  (Local/Distributed)  |              |   (Render Cloud)    |              +-----------------------+
+-----------------------+              +----------+----------+
                                                  |
                 +--------------------------------+--------------------------------+
                 |                                |                                |
                 v                                v                                v
     +-----------------------+        +-----------------------+        +-----------------------+
     |  XGBoost Classifier   |        |   Isolation Forest    |        | HuggingFace NLP Model |
     |  (Supervised Risk)    |        |   (Anomaly Scoring)   |        |  (Text Intent Model)  |
     +-----------------------+        +-----------------------+        +-----------------------+
```

---

## 🧩 Components

1. **Backend (`Backend/`)**: Dockerized Python 3.11 FastAPI server running XGBoost, Isolation Forest, HuggingFace Transformer model (`aishuzaman/phishguard-nlp-v2`), WHOIS engine, Google Safe Browsing, and VirusTotal threat intelligence.
2. **Web Portal (`web/`)**: React + Vite Cyber Dark Web Dashboard for URL inspection, text intent analysis, and scan history.
3. **Chrome Extension (`Extension/`)**: Manifest V3 extension intercepting high-risk navigation and scanning pages in real-time.
