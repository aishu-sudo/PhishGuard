import requests

from app.config import GOOGLE_API_KEY


def check_safe_browsing(url):
    if not GOOGLE_API_KEY:
        return {"status": "not_configured", "flagged": None}

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={GOOGLE_API_KEY}"
    )

    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=5)

        if response.status_code == 400:
            return {"status": "invalid_request", "flagged": None}
        if response.status_code == 403:
            return {"status": "invalid_api_key", "flagged": None}
        if response.status_code == 429:
            return {"status": "rate_limited", "flagged": None}
        if response.status_code != 200:
            return {"status": "error", "code": response.status_code, "flagged": None}

        data = response.json()
        return {"status": "ok", "flagged": "matches" in data}

    except requests.RequestException as e:
        return {"status": "network_error", "message": str(e), "flagged": None}