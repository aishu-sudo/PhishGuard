import base64
import requests


def check_virustotal(url, api_key, auto_submit=True):
    if not api_key:
        return {"status": "not_configured"}

    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=6
        )

        if resp.status_code == 200:
            return resp.json()["data"]["attributes"]["last_analysis_stats"]

        if resp.status_code == 404:
            if not auto_submit:
                return {"status": "not_scanned"}

            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            if submit_resp.status_code == 200:
                return {
                    "status": "submitted",
                    "message": "URL submitted to VirusTotal. Try again later."
                }
            if submit_resp.status_code == 429:
                return {"status": "rate_limited"}
            return {"status": "submit_failed", "code": submit_resp.status_code}

        if resp.status_code == 401:
            return {"status": "invalid_api_key"}

        if resp.status_code == 429:
            return {"status": "rate_limited"}

        return {"status": "error", "code": resp.status_code}

    except requests.RequestException as e:
        return {"status": "network_error", "message": str(e)}