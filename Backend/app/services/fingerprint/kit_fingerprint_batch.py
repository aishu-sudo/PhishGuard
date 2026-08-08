"""
HTML/JS Kit Fingerprinting — Batch
--------------------------------------
Extends favicon comparison with structural HTML similarity across the
same set of alive hosts already discovered by the subdomain pipeline.
No new external tool dependency — reuses plain requests + difflib.
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher

import requests

_HEADERS = {"User-Agent": "Mozilla/5.0 (PhishGuard-Fingerprint)"}


def _tag_skeleton(html):
    html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
    tags = re.findall(r"<\s*([a-zA-Z0-9]+)", html)
    return " ".join(tags).lower()


def _fetch_skeleton(host, timeout=6):
    try:
        resp = requests.get(
            f"https://{host}", timeout=timeout, headers=_HEADERS, allow_redirects=True
        )
        if resp.status_code != 200:
            return host, None, f"status_{resp.status_code}"
        skeleton = _tag_skeleton(resp.text)
        return host, skeleton, None
    except requests.RequestException as e:
        return host, None, str(e)


def compare_html_structure(hosts, similarity_threshold=0.85, max_workers=10):
    """
    Fetches each host's page skeleton and groups hosts whose structural
    similarity exceeds the threshold — a same-template signal
    independent of favicon.
    """
    skeletons = {}
    errors = {}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_fetch_skeleton, h) for h in hosts]
        for future in as_completed(futures):
            host, skeleton, err = future.result()
            if skeleton:
                skeletons[host] = skeleton
            else:
                errors[host] = err

    hosts_list = list(skeletons.keys())
    groups = []
    assigned = set()

    for i in range(len(hosts_list)):
        if hosts_list[i] in assigned:
            continue
        cluster = [hosts_list[i]]
        for j in range(i + 1, len(hosts_list)):
            if hosts_list[j] in assigned:
                continue
            ratio = SequenceMatcher(
                None, skeletons[hosts_list[i]], skeletons[hosts_list[j]]
            ).ratio()
            if ratio >= similarity_threshold:
                cluster.append(hosts_list[j])
                assigned.add(hosts_list[j])
        if len(cluster) > 1:
            assigned.add(hosts_list[i])
            groups.append({
                "similarity_threshold": similarity_threshold,
                "shared_by": cluster,
            })

    return {
        "status": "ok",
        "checked_count": len(hosts),
        "structural_duplicate_groups": groups,
        "errors": errors,
    }