
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from app.services.fingerprint.kit_fingerprint_batch import compare_html_structure
from app.services.whois_service import get_whois_info
from app.services.dns_service import get_dns_info
from app.services.ssl_service import get_ssl_info
from app.services.redirect_service import get_redirect_chain
from app.services.ip_service import get_ip_info
from app.services.safe_browsing import check_safe_browsing
from app.services.virustotal_service import check_virustotal
from app.services.correlation.cert_transparency import get_cert_history
from app.services.correlation.reverse_ip import get_shared_hosts
from app.services.correlation.subdomain_pipeline import run_subdomain_pipeline
from app.services.fingerprint.favicon_batch import compare_favicons
from app.services.correlation.db import (
    save_domain,
    save_domains_bulk,
    find_existing_cluster_for_domain,
    get_next_cluster_id,
)

from app.config import VT_API_KEY, VT_AUTO_SUBMIT

_MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "co.in", "co.kr",
    "com.au", "com.br", "com.bd", "com.pk", "com.tr", "com.mx", "com.sg",
    "com.hk", "com.tw", "co.za", "co.nz", "com.ar", "com.ua", "net.au",
}


def _safe_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}


def _apex_domain(host):
    """Registrable domain. The old version only stripped 'www.', so
    app.notion.com stayed app.notion.com and subdomain enumeration was run
    against a subdomain instead of the apex."""
    if not host:
        return host
    host = host.lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _extract_alive_hosts(subdomain_result):
    """Bare hostnames from the alive-check results."""
    if not isinstance(subdomain_result, dict):
        return []
    alive_entries = (subdomain_result.get("alive_check") or {}).get("alive") or []
    hosts = []
    for entry in alive_entries:
        host = entry.get("input_host")
        if not host:
            url = entry.get("url")
            if url:
                host = urlparse(url).hostname
        if host and host not in hosts:
            hosts.append(host.lower().rstrip("."))
    return hosts


def _persist_cluster_findings(host, cert_result, reverse_ip_result, subdomain_result):
    try:
        cluster_id = find_existing_cluster_for_domain(host)
        if cluster_id is None:
            cluster_id = get_next_cluster_id()

        save_domain(host, source="user_input", cluster_id=cluster_id)

        if isinstance(cert_result, dict) and cert_result.get("related"):
            related = cert_result.get("related_domains") or []
            if related:
                save_domains_bulk(related, source="crt.sh", cluster_id=cluster_id)

        if isinstance(reverse_ip_result, dict) and reverse_ip_result.get("related"):
            domains = reverse_ip_result.get("domains") or []
            if domains:
                save_domains_bulk(domains, source="reverse_ip", cluster_id=cluster_id)

        alive_names = _extract_alive_hosts(subdomain_result)
        if alive_names:
            save_domains_bulk(alive_names, source="subfinder", cluster_id=cluster_id)

        return cluster_id
    except Exception as e:
        return {"error": str(e)}


def investigate(url, depth="full"):
    """
    depth="fast"  -> cheap, ~1-3s. Safe to call in the blocking request path.
    depth="full"  -> adds infrastructure clustering. Call this lazily.
    """
    host = urlparse(url if "://" in url else "http://" + url).hostname
    if not host:
        return {"status": "error", "error": "could not parse hostname", "url": url}

    host = host.lower().rstrip(".")
    apex = _apex_domain(host)

    # ---------------- Stage 1: cheap lookups, all in parallel ----------------
    with ThreadPoolExecutor(max_workers=7) as ex:
        f_whois = ex.submit(_safe_call, get_whois_info, host)
        f_dns = ex.submit(_safe_call, get_dns_info, host)
        f_ssl = ex.submit(_safe_call, get_ssl_info, host)
        f_redir = ex.submit(_safe_call, get_redirect_chain, url)
        f_ip = ex.submit(_safe_call, get_ip_info, host)
        f_sb = ex.submit(_safe_call, check_safe_browsing, url)
        f_vt = ex.submit(
            _safe_call, check_virustotal, url,
            api_key=VT_API_KEY, auto_submit=VT_AUTO_SUBMIT,
        )

        whois_info = f_whois.result()
        dns_info = f_dns.result()
        ssl_info = f_ssl.result()
        redirects = f_redir.result()
        ip_info = f_ip.result()
        sb_info = f_sb.result()
        vt_info = f_vt.result()

    report = {
        "url": url,
        "host": host,
        "apex": apex,
        "depth": depth,
        "whois": whois_info,
        "dns": dns_info,
        "ssl": ssl_info,
        "redirects": redirects,
        "ip": ip_info,
        "safe_browsing": sb_info,
        "virustotal": vt_info,
        "disclaimer": (
            "This report aggregates open-source signals to support human "
            "investigation. It does not identify or de-anonymize an attacker."
        ),
    }

    if depth != "full":
        report["infrastructure_cluster"] = {"status": "not_requested"}
        return report

    # ---------------- Stage 2: clustering, also in parallel ----------------
    resolved_ips = []
    if isinstance(ip_info, dict):
        resolved_ips = ip_info.get("ipv4") or (
            [ip_info["ip"]] if ip_info.get("ip") else []
        )
    hosting_provider = ip_info.get("hosting") if isinstance(ip_info, dict) else None
    asn = ip_info.get("asn") if isinstance(ip_info, dict) else None

    with ThreadPoolExecutor(max_workers=3) as ex:
        f_cert = ex.submit(_safe_call, get_cert_history, host)
        f_subs = ex.submit(_safe_call, run_subdomain_pipeline, apex)

        if resolved_ips:
            f_rip = ex.submit(
                _safe_call, get_shared_hosts, resolved_ips[0],
                hosting_provider=hosting_provider, asn=asn,
            )
        else:
            f_rip = None

        cert_result = f_cert.result()
        subdomain_result = f_subs.result()
        reverse_ip_result = (
            f_rip.result() if f_rip
            else {"status": "skipped", "reason": "no resolved IP available"}
        )

    if isinstance(reverse_ip_result, dict) and len(resolved_ips) > 1:
        reverse_ip_result["additional_ips_not_queried"] = resolved_ips[1:]

    alive_hosts = _extract_alive_hosts(subdomain_result)
    if host not in alive_hosts:
        alive_hosts.append(host)

    favicon_comparison = (
        _safe_call(compare_favicons, alive_hosts) if alive_hosts
        else {"status": "skipped"}
    )
    
    html_structure_comparison = (
        _safe_call(compare_html_structure, alive_hosts) if alive_hosts
        else {"status": "skipped"}
    )

    report["cluster_id"] = _persist_cluster_findings(
        host, cert_result, reverse_ip_result, subdomain_result
    )
    report["infrastructure_cluster"] = {
        "certificate_transparency": cert_result,
        "shared_hosting": reverse_ip_result,
        "subdomain_discovery": subdomain_result,
        "favicon_comparison": favicon_comparison,
        "html_structure_comparison": html_structure_comparison,
    }
    return report