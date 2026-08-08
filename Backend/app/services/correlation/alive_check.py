"""
HTTP liveness check.

FIXES vs old version
--------------------
1. Hardcoded binary name "pdhttpx". That is the Debian/Kali *package rename*
   of ProjectDiscovery httpx. Your Kali shell uses `httpx`; on Windows it is
   `httpx.exe`. shutil.which("pdhttpx") returned None, the function returned
   {"status": "tool_not_found"}, and the popup — which reads
   `alive_check.alive.length` — rendered a confident **0**. That is the
   "0 alive" lie. We now probe several names and honour HTTPX_PATH.

2. No fallback. If no binary exists, liveness is now checked in pure Python
   with requests + a thread pool. The stage always produces real data.

3. The empty-input early return omitted `alive_count`, so callers doing
   .get("alive_count", 0) could not distinguish "checked nothing" from
   "checked and found nothing". Shape is now consistent on every path.

4. Distinguishes "not checked" from "checked, nothing alive" via `checked_count`
   and an explicit `method` field, so the UI can never present an unrun check
   as a negative result.
"""

import os
import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

HTTPX_CANDIDATES = ["httpx", "pdhttpx", "httpx.exe", "httpx-toolkit"]
DEFAULT_TIMEOUT = 60
PY_TIMEOUT = 6
PY_MAX_WORKERS = 20

_TITLE_LIMIT = 120


def _find_binary():
    override = os.getenv("HTTPX_PATH")
    if override and os.path.isfile(override):
        return override
    for name in HTTPX_CANDIDATES:
        found = shutil.which(name)
        if found:
            # `httpx` may resolve to the *Python* httpx CLI, which does not
            # accept -silent. Verify it is the ProjectDiscovery tool.
            try:
                probe = subprocess.run(
                    [found, "-version"], capture_output=True, text=True, timeout=10
                )
                blob = (probe.stdout + probe.stderr).lower()
                if "projectdiscovery" in blob or "httpx" in blob:
                    return found
            except Exception:
                continue
    return None


# ----------------------------------------------------------------------
# Pure-Python fallback
# ----------------------------------------------------------------------

def _probe_one(host, timeout=PY_TIMEOUT):
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (PhishGuard-Investigator)"},
            )
        except requests.RequestException:
            continue

        title = None
        ctype = resp.headers.get("Content-Type", "")
        if "html" in ctype.lower():
            body = resp.text[:20000]
            low = body.lower()
            start = low.find("<title")
            if start != -1:
                gt = low.find(">", start)
                end = low.find("</title>", gt)
                if gt != -1 and end != -1:
                    title = body[gt + 1:end].strip()[:_TITLE_LIMIT]

        return {
            "url": resp.url,
            "input_host": host,
            "status_code": resp.status_code,
            "title": title,
            "scheme": scheme,
            "final_host": requests.utils.urlparse(resp.url).hostname,
        }
    return None


def _check_alive_python(hosts, timeout=PY_TIMEOUT):
    alive = []
    with ThreadPoolExecutor(max_workers=min(PY_MAX_WORKERS, len(hosts))) as ex:
        futures = [ex.submit(_probe_one, h, timeout) for h in hosts]
        for future in as_completed(futures):
            try:
                entry = future.result()
            except Exception:
                entry = None
            if entry:
                alive.append(entry)
    alive.sort(key=lambda e: e.get("input_host") or "")
    return {
        "status": "ok",
        "method": "python_requests",
        "checked_count": len(hosts),
        "alive_count": len(alive),
        "alive": alive,
    }


# ----------------------------------------------------------------------

def check_alive(domains, timeout=DEFAULT_TIMEOUT):
    hosts = sorted({
        d.strip().lower().rstrip("/")
        for d in (domains or []) if d and d.strip()
    })

    if not hosts:
        return {
            "status": "ok",
            "method": "none",
            "checked_count": 0,
            "alive_count": 0,
            "alive": [],
            "note": "No resolving hosts were supplied, so no liveness check ran.",
        }

    binary = _find_binary()
    if not binary:
        result = _check_alive_python(hosts)
        result["httpx_status"] = "tool_not_found"
        result["note"] = (
            "ProjectDiscovery httpx not found on PATH; used the built-in "
            "Python prober instead. Set HTTPX_PATH to use httpx."
        )
        return result

    try:
        proc = subprocess.run(
            [binary, "-silent", "-json", "-status-code", "-title",
             "-no-color", "-timeout", "6"],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        result = _check_alive_python(hosts)
        result["httpx_status"] = "timeout"
        return result
    except Exception as e:
        result = _check_alive_python(hosts)
        result["httpx_status"] = "error"
        result["httpx_error"] = str(e)
        return result

    alive = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        alive.append({
            "url": entry.get("url"),
            "input_host": entry.get("input") or entry.get("host"),
            # httpx v1.3+ uses "status_code"; older builds use "status-code"
            "status_code": entry.get("status_code") or entry.get("status-code"),
            "title": (entry.get("title") or None),
            "webserver": entry.get("webserver"),
        })

    # httpx ran but produced nothing parseable -> verify with the Python prober
    # rather than reporting a false zero.
    if not alive:
        result = _check_alive_python(hosts)
        result["httpx_status"] = "no_output"
        result["httpx_stderr"] = (proc.stderr or "").strip()[:300]
        return result

    return {
        "status": "ok",
        "method": "httpx",
        "binary": binary,
        "checked_count": len(hosts),
        "alive_count": len(alive),
        "alive": alive,
    }