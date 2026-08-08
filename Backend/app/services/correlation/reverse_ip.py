import ipaddress
import requests


# ----------------------------------------------------------------
# Backend: HackerTarget (one possible data source among several)
# ----------------------------------------------------------------

def _query_hackertarget(ip, timeout=10):
    resp = requests.get(
        f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
        timeout=timeout,
    )

    if resp.status_code != 200:
        return {
            "status": "http_error",
            "status_code": resp.status_code,
        }

    text = resp.text.strip()
    text_lower = text.lower()

    if text_lower.startswith("error"):
        return {"status": "provider_error", "raw": text}

    if "api count exceeded" in text_lower:
        return {"status": "rate_limited", "raw": text}

    if "no dns" in text_lower or not text:
        return {"status": "no_shared_hosts_found", "domains": []}

    domains = sorted({
        d.strip().lower()
        for d in text.splitlines()
        if d.strip()
    })

    return {"status": "ok", "domains": domains}


# ----------------------------------------------------------------
# Verdict scoring
# ----------------------------------------------------------------

_CDN_PROVIDERS = {
    "cloudflare": "Cloudflare",
    "amazon": "Amazon/AWS",
    "google": "Google Cloud",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "vercel": "Vercel",
    "netlify": "Netlify",
}


def _match_cdn_provider(hosting_provider):
    if not hosting_provider:
        return None
    hosting_lower = hosting_provider.lower()
    for key, label in _CDN_PROVIDERS.items():
        if key in hosting_lower:
            return label
    return None


def _score_shared_hosting(domain_count, hosting_provider=None, asn=None):

    matched_provider = _match_cdn_provider(hosting_provider)

    if domain_count == 0:
        return {
            "shared_hosting": False,
            "related": False,
            "confidence": "NONE",
            "reason": "No other domains found on this IP.",
        }

    if matched_provider:
        asn_suffix = f" (AS{asn})" if asn else ""
        return {
            "shared_hosting": True,
            "related": False,
            "confidence": "LOW",
            "reason": (
                f"IP belongs to {matched_provider}{asn_suffix}, a shared CDN "
                f"provider. Reverse IP lookup identifies numerous unrelated "
                f"domains on the same infrastructure. Therefore, IP sharing "
                f"alone is not a meaningful attribution signal."
            ),
        }

    if domain_count > 20:
        return {
            "shared_hosting": True,
            "related": False,
            "confidence": "LOW",
            "reason": (
                f"At least {domain_count} unrelated domains share this IP "
                f"(reverse-IP results are frequently capped and change over "
                f"time, so the true count may be higher) — likely large "
                f"shared hosting, low correlation value on its own."
            ),
        }

    if domain_count <= 5:
        return {
            "shared_hosting": True,
            "related": None,
            "confidence": "MEDIUM",
            "reason": (
                f"Only {domain_count} domain(s) share this IP — small "
                f"enough to be dedicated/low-tenant hosting, worth "
                f"cross-checking against certificate and WHOIS data."
            ),
        }

    return {
        "shared_hosting": True,
        "related": None,
        "confidence": "MEDIUM",
        "reason": (
            f"{domain_count} domains share this IP — moderate hosting "
            f"density, inconclusive without further correlation."
        ),
    }


# ----------------------------------------------------------------
# Public service interface
# ----------------------------------------------------------------

def get_shared_hosts(ip, hosting_provider=None, asn=None, timeout=10):

    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return {"status": "invalid_ip", "input": ip}

    result = _query_hackertarget(ip, timeout=timeout)

    if result.get("status") != "ok":
        return result

    domains = result["domains"]
    verdict = _score_shared_hosting(len(domains), hosting_provider, asn=asn)

    return {
        "status": "ok",
        "shared_host_count": len(domains),
        "domains": domains,
        **verdict,
    }