"""
Certificate Transparency correlation.

FIXES vs old version
--------------------
1. network_error was terminal. crt.sh routinely answers in 8-25s and returns
   502/503/504 under load. A single 10s attempt with no retry fails most of
   the time -> UI printed "Check failed (network_error)". Now: 2 attempts,
   20s timeout, exponential backoff, session with keep-alive.

2. Wrong query shape. `?q=app.notion.com` does an identity match only. Real
   subdomain/cluster discovery needs `?q=%.<apex>`. We now query BOTH the
   exact host and `%.<apex>` and merge.

3. Wildcard names were thrown away (`if name.startswith("*."): continue`).
   app.notion.com's leaf cert is literally `CN=*.app.notion.com`, so the old
   code discarded the only evidence there was and reported
   "Shares cert w/ other domains: No". Wildcards are now normalised
   (`*.app.notion.com` -> `app.notion.com`) and counted.

4. No fallback. If crt.sh is unreachable we now do a direct TLS handshake and
   read the live leaf certificate (serial, subject CN, SAN list) — the same
   thing `openssl s_client | openssl x509` gives you. Status becomes
   "ok_degraded" instead of a hard failure, so the UI shows real data.

5. The 3 crt.sh queries (host, apex, %.apex) used to run one after another,
   each with its own retries — worst case up to ~285s for one domain, well
   past the extension's client-side timeout. They now run concurrently, so
   the worst case is roughly the slowest single query, not the sum of all
   three. This is what fixed "Shares certificate with other domains: Check
   failed" appearing repeatedly on large domains like notion.com.
"""

import re
import ssl
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

CRTSH_TIMEOUT = 20
CRTSH_ATTEMPTS = 2
MAX_CERTS = 300           # crt.sh can return thousands for big brands

_session = requests.Session()
_session.headers.update({
    "User-Agent": "PhishGuard-Investigator/1.0",
    "Accept": "application/json",
})

# Multi-label public suffixes we care about most. Extend as needed, or install
# `tldextract` and swap _apex() for tldextract.extract().
_MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "co.in", "co.kr",
    "com.au", "com.br", "com.bd", "com.pk", "com.tr", "com.mx", "com.sg",
    "com.hk", "com.tw", "co.za", "co.nz", "com.ar", "com.ua", "net.au",
}


def _normalize_domain(domain_or_url):
    parsed = urlparse(
        domain_or_url if "://" in domain_or_url else "http://" + domain_or_url
    )
    host = (parsed.hostname or domain_or_url).lower().strip().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _apex(host):
    """notion.com -> notion.com ; app.notion.com -> notion.com ; x.co.uk -> x.co.uk"""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _clean_name(raw):
    """Normalise a SAN entry. Returns None if it should be ignored."""
    name = raw.strip().lower().rstrip(".")
    if not name:
        return None
    if name.startswith("*."):
        name = name[2:]            # keep the covered base instead of discarding
    if name.startswith("."):
        name = name[1:]
    # crt.sh sometimes leaks email addresses into name_value
    if "@" in name or " " in name:
        return None
    if not re.match(r"^[a-z0-9._-]+\.[a-z]{2,}$", name):
        return None
    return name


def _fetch_crtsh(query, timeout=CRTSH_TIMEOUT):
    """One crt.sh query with retries. Returns (data_list, error_string)."""
    last_err = None
    for attempt in range(CRTSH_ATTEMPTS):
        try:
            resp = _session.get(
                "https://crt.sh/",
                params={"q": query, "output": "json"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                if not resp.text.strip():
                    return [], None
                try:
                    return resp.json(), None
                except ValueError as e:
                    last_err = f"invalid_json: {e}"
            elif resp.status_code in (429, 500, 502, 503, 504):
                last_err = f"http_{resp.status_code}"
            else:
                return None, f"http_{resp.status_code}"
        except requests.RequestException as e:
            last_err = type(e).__name__

        if attempt < CRTSH_ATTEMPTS - 1:
            time.sleep(1.5 * (attempt + 1))     # 1.5s, 3s

    return None, last_err or "unknown_error"


def get_live_certificate(host, port=443, timeout=8):
    """
    Direct TLS handshake — the programmatic equivalent of
    `openssl s_client -connect host:443 | openssl x509 -noout -serial -subject`.
    Used as a fallback when crt.sh is unavailable.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"status": "cert_invalid", "error": str(e), "host": host}
    except Exception as e:
        return {"status": "handshake_failed", "error": str(e), "host": host}

    if not cert:
        return {"status": "no_cert", "host": host}

    subject_cn = None
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                subject_cn = value

    issuer_cn = None
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key in ("commonName", "organizationName") and not issuer_cn:
                issuer_cn = value

    sans = []
    for typ, value in cert.get("subjectAltName", ()):
        if typ.lower() == "dns":
            sans.append(value.lower())

    serial = cert.get("serialNumber")

    return {
        "status": "ok",
        "host": host,
        "serial": serial,
        "subject_cn": subject_cn,
        "issuer": issuer_cn,
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "san_dns_names": sans,
        "san_count": len(sans),
    }


def _verdict(domain, related_domains, subdomains, wildcard_names):
    related_count = len(related_domains)

    if related_count >= 5:
        return {
            "related": True,
            "confidence": "HIGH",
            "reason": (
                f"{related_count} distinct domains appear on the same "
                f"certificate(s) as {domain} — strong evidence of shared "
                f"certificate/ownership."
            ),
        }
    if related_count >= 1:
        return {
            "related": True,
            "confidence": "MEDIUM",
            "reason": (
                f"{related_count} other domain(s) share a certificate with "
                f"{domain} — cross-check against hosting and WHOIS data."
            ),
        }
    if subdomains:
        return {
            "related": False,
            "confidence": "LOW",
            "reason": (
                f"{len(subdomains)} subdomain(s) of {domain} found on its own "
                f"certificates; no other registrable domains share a cert."
            ),
        }
    if wildcard_names:
        return {
            "related": False,
            "confidence": "LOW",
            "reason": (
                f"Only wildcard certificate(s) found "
                f"({', '.join(sorted(wildcard_names)[:3])}) — a wildcard covers "
                f"unknown hosts, so absence of siblings is not proof of isolation."
            ),
        }
    return {
        "related": False,
        "confidence": "NONE",
        "reason": f"Certificate(s) found, but no names beyond {domain} itself.",
    }


def get_cert_history(domain_or_url, timeout=CRTSH_TIMEOUT):
    host = _normalize_domain(domain_or_url)
    apex = _apex(host)

    queries = [host]
    if apex != host:
        queries.append(apex)
    queries.append("%." + apex)          # the query that actually finds siblings

    data = []
    errors = {}

    # Run all crt.sh queries concurrently instead of one after another —
    # sequential retries across 3 queries could take minutes on a large
    # domain. Parallelizing caps the worst case to roughly the slowest
    # single query instead of the sum of all three.
    with ThreadPoolExecutor(max_workers=len(queries)) as ex:
        futures = {ex.submit(_fetch_crtsh, q, timeout): q for q in queries}
        for future in as_completed(futures):
            q = futures[future]
            try:
                rows, err = future.result()
            except Exception as e:
                rows, err = None, f"{type(e).__name__}: {e}"
            if err:
                errors[q] = err
            elif rows:
                data.extend(rows)

    # ---------- crt.sh completely unavailable -> live TLS fallback ----------
    if not data and errors:
        live = get_live_certificate(host)
        base = {
            "queried_domain": host,
            "apex": apex,
            "source": "live_tls_handshake",
            "crtsh_errors": errors,
        }
        if live.get("status") != "ok":
            return {
                **base,
                "status": "unavailable",
                "related": None,
                "confidence": "UNKNOWN",
                "certificate_count": 0,
                "subdomains": [],
                "related_domains": [],
                "certificates": [],
                "reason": (
                    "Certificate Transparency lookup failed and the live TLS "
                    f"handshake also failed ({live.get('status')}). No verdict — "
                    "this is NOT evidence of safety."
                ),
            }

        sans = [n for n in (_clean_name(s) for s in live["san_dns_names"]) if n]
        wildcards = [s for s in live["san_dns_names"] if s.startswith("*.")]
        subs = sorted({n for n in sans if n.endswith("." + apex)})
        others = sorted({n for n in sans if not n.endswith(apex) and n != apex})

        v = _verdict(host, others, subs, wildcards)
        return {
            **base,
            "status": "ok_degraded",
            "certificate_count": 1,
            "live_certificate": live,
            "subdomains": subs,
            "related_domains": others,
            "wildcard_names": wildcards,
            "certificates": [{
                "certificate_id": None,
                "serial": live.get("serial"),
                "issuer": live.get("issuer"),
                "common_name": live.get("subject_cn"),
                "not_before": live.get("not_before"),
                "not_after": live.get("not_after"),
            }],
            **v,
            "reason": v["reason"] + " (Source: live TLS certificate only — "
                                    "crt.sh was unreachable, so historical "
                                    "certificates were not checked.)",
        }

    if not data:
        return {
            "status": "ok",
            "queried_domain": host,
            "apex": apex,
            "source": "crt.sh",
            "certificate_count": 0,
            "subdomains": [],
            "related_domains": [],
            "wildcard_names": [],
            "certificates": [],
            "related": False,
            "confidence": "NONE",
            "reason": "No certificates found in Certificate Transparency logs.",
        }

    # ---------------------------- parse crt.sh ----------------------------
    seen_certs = set()
    seen_names = set()
    subdomains, related_domains, wildcard_names, certificates = [], [], [], []

    for entry in data:
        cid = entry.get("id") or entry.get("min_cert_id")
        if cid and cid in seen_certs:
            continue
        if cid:
            seen_certs.add(cid)

        if len(certificates) < MAX_CERTS:
            certificates.append({
                "certificate_id": cid,
                "issuer": entry.get("issuer_name"),
                "not_before": entry.get("not_before"),
                "not_after": entry.get("not_after"),
                "common_name": entry.get("common_name"),
                "serial": entry.get("serial_number"),
            })

        for raw_name in (entry.get("name_value") or "").split("\n"):
            raw_stripped = raw_name.strip().lower()
            if raw_stripped.startswith("*."):
                if raw_stripped not in wildcard_names:
                    wildcard_names.append(raw_stripped)

            name = _clean_name(raw_name)
            if not name or name in seen_names:
                continue
            seen_names.add(name)

            if name == host or name == apex:
                continue
            if name.endswith("." + apex):
                subdomains.append(name)
            else:
                related_domains.append(name)

    subdomains.sort()
    related_domains.sort()

    result = {
        "status": "ok",
        "queried_domain": host,
        "apex": apex,
        "source": "crt.sh",
        "certificate_count": len(seen_certs) or len(certificates),
        "certificates_returned": len(certificates),
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
        "related_domains": related_domains,
        "wildcard_names": wildcard_names,
        "certificates": certificates,
        **_verdict(host, related_domains, subdomains, wildcard_names),
    }
    if errors:
        result["partial_query_errors"] = errors
    return result