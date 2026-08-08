"""
Redirect Service
----------------
Follows the full redirect chain for a URL and reports every hop.
Note: cloaked phishing kits may detect this as a scanner request
and serve a clean page instead of the real payload.
"""

import requests


def get_redirect_chain(url, timeout=6):
    try:
        resp = requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (PhishGuard-Investigator)"},
        )
        chain = [r.url for r in resp.history] + [resp.url]
        return {
            "hops": chain,
            "hop_count": len(chain) - 1,
            "final_status_code": resp.status_code,
        }
    except Exception as e:
        return {"error": str(e)}