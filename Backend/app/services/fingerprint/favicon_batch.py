
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.services.fingerprint.favicon_hash import get_favicon_hash_direct


def _apex_of(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _fetch_one(host, apex_hash_cache):
    result = get_favicon_hash_direct(host)

    if result.get("status") != "ok":
        apex = _apex_of(host)
        if apex != host and apex in apex_hash_cache:
            apex_result = apex_hash_cache[apex]
            if apex_result.get("status") == "ok":
                fallback = dict(apex_result)
                fallback["reason"] = f"used apex domain fallback ({apex})"
                return host, fallback

    return host, result


def compare_favicons(hosts, max_workers=10, per_request_timeout=5):
    hash_to_hosts = {}
    errors = {}

    # Compute each unique apex domain's favicon ONCE up front, so
    # per-host fallback lookups are free (just a dict read) instead
    # of triggering a fresh set of network requests every time.
    apex_domains = list({_apex_of(h) for h in hosts})
    apex_hash_cache = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(get_favicon_hash_direct, apex, per_request_timeout): apex
            for apex in apex_domains
        }
        for future in as_completed(futures):
            apex = futures[future]
            apex_hash_cache[apex] = future.result()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_fetch_one, host, apex_hash_cache)
            for host in hosts
        ]
        for future in as_completed(futures):
            host, result = future.result()
            if result.get("status") == "ok":
                h = result["hash"]
                hash_to_hosts.setdefault(h, []).append(host)
            else:
                errors[host] = result.get("status", "unknown")

    duplicate_groups = [
        {"favicon_hash": h, "shared_by": hosts_list}
        for h, hosts_list in hash_to_hosts.items()
        if len(hosts_list) > 1
    ]

    unique_count = sum(1 for hosts_list in hash_to_hosts.values() if len(hosts_list) == 1)

    return {
        "status": "ok",
        "checked_count": len(hosts),
        "duplicate_groups": duplicate_groups,
        "unique_count": unique_count,
        "errors": errors,
    }