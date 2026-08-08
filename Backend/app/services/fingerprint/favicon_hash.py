import codecs
import re
import requests
import mmh3
from urllib.parse import urljoin

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
}

_ICON_LINK_PATTERN = re.compile(
    r'<link[^>]+rel=["\'](?:shortcut icon|icon|apple-touch-icon)["\'][^>]*>',
    re.IGNORECASE,
)
_HREF_PATTERN = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


def _favicon_mmh3(content_bytes):
    b64 = codecs.encode(content_bytes, "base64")
    return mmh3.hash(b64)


def get_favicon_hash_direct(host, timeout=5):
    """
    Single-host favicon lookup, no apex fallback recursion.
    Kept fast and self-contained so batch comparisons can call it
    directly without triggering cascading requests.
    """
    base_url = f"https://{host}"

    try:
        resp = requests.get(
            f"{base_url}/favicon.ico", timeout=timeout, headers=_HEADERS, allow_redirects=True
        )
        if resp.status_code == 200 and resp.content:
            return {
                "status": "ok",
                "favicon_url": f"{base_url}/favicon.ico",
                "hash": _favicon_mmh3(resp.content),
            }
    except requests.RequestException:
        pass

    try:
        page = requests.get(base_url, timeout=timeout, headers=_HEADERS, allow_redirects=True)
    except requests.RequestException as e:
        return {"status": "network_error", "message": str(e)}

    if page.status_code != 200:
        return {"status": "error", "reason": f"homepage status {page.status_code}"}

    link_tag_match = _ICON_LINK_PATTERN.search(page.text)
    if not link_tag_match:
        return {"status": "not_found", "reason": "no favicon link found"}

    href_match = _HREF_PATTERN.search(link_tag_match.group(0))
    if not href_match:
        return {"status": "not_found", "reason": "icon link had no href"}

    favicon_url = urljoin(page.url, href_match.group(1))

    try:
        icon_resp = requests.get(favicon_url, timeout=timeout, headers=_HEADERS)
    except requests.RequestException as e:
        return {"status": "network_error", "message": str(e)}

    if icon_resp.status_code != 200 or not icon_resp.content:
        return {"status": "error", "reason": f"favicon fetch status {icon_resp.status_code}"}

    return {
        "status": "ok",
        "favicon_url": favicon_url,
        "hash": _favicon_mmh3(icon_resp.content),
    }


# Kept for backward compatibility with any other caller
def get_favicon_hash(host, timeout=8, fallback_apex=None):
    result = get_favicon_hash_direct(host, timeout=timeout)
    if result.get("status") == "ok" or not fallback_apex or fallback_apex == host:
        return result
    apex_result = get_favicon_hash_direct(fallback_apex, timeout=timeout)
    if apex_result.get("status") == "ok":
        apex_result["reason"] = f"used apex domain fallback ({fallback_apex})"
        return apex_result
    return result