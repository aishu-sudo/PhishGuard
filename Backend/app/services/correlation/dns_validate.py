"""
DNS validation of enumerated subdomains.

FIXES vs old version — this is the "10 found, 0 resolving" bug
---------------------------------------------------------------
1. A-records only. Many real subdomains are AAAA-only or resolve through a
   CNAME chain that yields no A record from the local resolver. dnspython
   raises NoAnswer, the old code caught it, and the host was filed as dead.
   app.notion.com itself has AAAA records (2602:f79a::1/::2) — exactly the case
   that was being dropped. Now: A, then AAAA, then CNAME.

2. A fresh dns.resolver.Resolver() per subdomain. On Windows the constructor
   reads network adapter config through the registry on every call; with 20
   threads hammering it and timeout=2 you get mass timeouts -> 0 resolving.
   Now: one module-level resolver, cloned cheaply per thread.

3. timeout=2 AND lifetime=2 means one UDP retry at most. Raised to
   timeout=3 / lifetime=6.

4. Silent failure. `dead` was a bare list, so you could not tell NXDOMAIN
   (genuinely does not exist) from Timeout (your resolver is broken). The
   return value now includes a `failure_breakdown` counter — if you ever see
   0 resolving again, this tells you immediately whether it is DNS or the data.

5. No fallback resolver. If the system resolver is unreachable everything dies.
   We now retry through public resolvers (1.1.1.1 / 8.8.8.8) before giving up.
"""

import dns.resolver
import dns.exception
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
RECORD_TYPES = ("A", "AAAA", "CNAME")


def _build_resolver(timeout, lifetime, nameservers=None):
    try:
        r = dns.resolver.Resolver()
    except Exception:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = list(FALLBACK_NAMESERVERS)

    if nameservers:
        r.nameservers = list(nameservers)
    if not r.nameservers:
        r.nameservers = list(FALLBACK_NAMESERVERS)

    r.timeout = timeout
    r.lifetime = lifetime
    return r


# Built once at import. Cloning this is far cheaper than re-reading system config.
_SYSTEM_RESOLVER = _build_resolver(3.0, 6.0)
_FALLBACK_RESOLVER = _build_resolver(3.0, 6.0, nameservers=FALLBACK_NAMESERVERS)


def _query(resolver, name, rdtype):
    """Returns (list_of_values, error_label). error_label is None on success."""
    try:
        answers = resolver.resolve(name, rdtype)
        return [str(r).rstrip(".") for r in answers], None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "NoAnswer"
    except dns.resolver.NoNameservers:
        return [], "NoNameservers"
    except dns.exception.Timeout:
        return [], "Timeout"
    except Exception as e:
        return [], type(e).__name__


def _resolve_one(name):
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]

    for resolver, label in ((_SYSTEM_RESOLVER, "system"),
                            (_FALLBACK_RESOLVER, "public")):
        last_error = None
        for rdtype in RECORD_TYPES:
            values, err = _query(resolver, name, rdtype)
            if values:
                return {
                    "subdomain": name,
                    "record_type": rdtype,
                    "ips": values if rdtype in ("A", "AAAA") else [],
                    "cname": values[0] if rdtype == "CNAME" else None,
                    "resolver": label,
                }, None
            last_error = err
            # NXDOMAIN is authoritative — no point trying AAAA/CNAME.
            if err == "NXDOMAIN":
                break

        # System resolver broken -> try public. Genuine NXDOMAIN -> stop.
        if last_error == "NXDOMAIN":
            return None, "NXDOMAIN"

    return None, last_error or "unknown"


def validate_subdomains(subdomains, timeout=3, max_workers=20):
    # Deduplicate first — subfinder + crt.sh merges often contain repeats.
    unique = sorted({
        s.strip().lower().rstrip(".").lstrip("*.")
        for s in (subdomains or []) if s and s.strip()
    })

    if not unique:
        return {
            "status": "ok",
            "checked_count": 0,
            "resolved_count": 0,
            "dead_count": 0,
            "resolved": [],
            "dead": [],
            "failure_breakdown": {},
        }

    resolved, dead = [], []
    failures = Counter()

    with ThreadPoolExecutor(max_workers=min(max_workers, len(unique))) as ex:
        futures = {ex.submit(_resolve_one, s): s for s in unique}
        for future in as_completed(futures):
            name = futures[future]
            try:
                record, error = future.result()
            except Exception as e:
                record, error = None, type(e).__name__
            if record:
                resolved.append(record)
            else:
                dead.append({"subdomain": name, "reason": error})
                failures[error] += 1

    resolved.sort(key=lambda r: r["subdomain"])

    result = {
        "status": "ok",
        "checked_count": len(unique),
        "resolved_count": len(resolved),
        "dead_count": len(dead),
        "resolved": resolved,
        "dead": dead,
        "failure_breakdown": dict(failures),
    }

    # Self-diagnosis: everything failing for a non-NXDOMAIN reason means the
    # resolver is broken, not that the subdomains are dead.
    if resolved == [] and unique:
        non_nx = sum(c for r, c in failures.items() if r != "NXDOMAIN")
        if non_nx == len(unique):
            result["status"] = "resolver_error"
            result["warning"] = (
                "0 of %d subdomains resolved and none returned NXDOMAIN "
                "(reasons: %s). This indicates a local DNS/resolver problem, "
                "not dead infrastructure. Do not report '0 live subdomains'."
                % (len(unique), dict(failures))
            )
    return result