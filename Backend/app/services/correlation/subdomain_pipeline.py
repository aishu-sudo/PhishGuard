"""
Subdomain discovery pipeline: enumerate -> resolve -> probe liveness.

FIXES vs old version
--------------------
1. MAX_SUBDOMAINS_TO_CHECK = 20 silently truncated. For notion.com (135 found)
   you would only ever see up to 20 checked, then the UI printed the resolved
   count as if it were the whole picture. Raised to 60, and the cap is now
   surfaced in the response *and* in a human-readable summary string.

2. A failed enumeration returned status "partial" with skipped stages, but the
   popup did not read that field — so a total failure looked identical to
   "nothing found". Now every response carries `summary` and `reliable`, so a
   consumer cannot accidentally present an unrun check as a zero.

3. Enumeration and validation results are now cross-checked: if DNS validation
   reports resolver_error, `reliable` is False and the counts are not to be
   trusted.
"""

import os

from app.services.correlation.subdomain_enum import run_subfinder
from app.services.correlation.dns_validate import validate_subdomains
from app.services.correlation.alive_check import check_alive

MAX_SUBDOMAINS_TO_CHECK = int(os.getenv("PG_MAX_SUBDOMAINS", "60"))


def _summary(found, checked, resolved, alive, capped):
    parts = [f"{found} found"]
    if capped:
        parts.append(f"{checked} checked (capped)")
    parts.append(f"{resolved} resolving")
    parts.append(f"{alive} alive")
    return ", ".join(parts)


def run_subdomain_pipeline(domain, max_check=MAX_SUBDOMAINS_TO_CHECK):
    enum_result = run_subfinder(domain)

    if enum_result.get("status") != "ok":
        return {
            "status": "failed",
            "reliable": False,
            "summary": (
                f"Subdomain enumeration did not run "
                f"({enum_result.get('status')}) — no conclusion available."
            ),
            "subfinder": enum_result,
            "dns_validation": {"status": "skipped"},
            "alive_check": {"status": "skipped"},
            "total_subdomains_found": None,
            "subdomains_checked": 0,
            "resolved_count": None,
            "alive_count": None,
        }

    all_subdomains = enum_result.get("subdomains", [])
    subdomains = all_subdomains[:max_check]
    capped = len(all_subdomains) > max_check

    if not subdomains:
        return {
            "status": "ok",
            "reliable": True,
            "summary": f"0 found for {domain} (enumeration ran successfully).",
            "subfinder": enum_result,
            "dns_validation": {
                "status": "ok", "checked_count": 0,
                "resolved_count": 0, "resolved": [],
            },
            "alive_check": {
                "status": "ok", "checked_count": 0,
                "alive_count": 0, "alive": [],
            },
            "total_subdomains_found": 0,
            "subdomains_checked": 0,
            "resolved_count": 0,
            "alive_count": 0,
            "capped": False,
        }

    dns_result = validate_subdomains(subdomains)
    resolved_names = [r["subdomain"] for r in dns_result.get("resolved", [])]

    dns_ok = dns_result.get("status") == "ok"

    alive_result = (
        check_alive(resolved_names) if resolved_names
        else {"status": "ok", "method": "none", "checked_count": 0,
              "alive_count": 0, "alive": [],
              "note": "No hosts resolved, so nothing was probed."}
    )

    resolved_count = dns_result.get("resolved_count", 0)
    alive_count = alive_result.get("alive_count", 0)

    reliable = dns_ok and alive_result.get("status") == "ok"

    result = {
        "status": "ok" if reliable else "degraded",
        "reliable": reliable,
        "summary": _summary(
            len(all_subdomains), len(subdomains), resolved_count, alive_count, capped
        ),
        "subfinder": enum_result,
        "dns_validation": dns_result,
        "alive_check": alive_result,
        "total_subdomains_found": len(all_subdomains),
        "subdomains_checked": len(subdomains),
        "resolved_count": resolved_count,
        "alive_count": alive_count,
        "capped": capped,
        "source": enum_result.get("tool"),
    }

    if not dns_ok:
        result["warning"] = dns_result.get(
            "warning", "DNS validation was unreliable; counts may be wrong."
        )
    return result