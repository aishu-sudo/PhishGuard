import os
import shutil
import subprocess

SUBFINDER_CANDIDATES = ["subfinder", "subfinder.exe"]
DEFAULT_TIMEOUT = 120


def _find_binary(candidates, env_var=None):
    if env_var:
        override = os.getenv(env_var)
        if override and os.path.isfile(override):
            return override
    for name in candidates:
        found = shutil.which(name)
        if found:
            return found
    return None


def _clean(lines, domain):
    """Normalise subfinder output: lowercase, drop wildcards, dedupe, in-scope only."""
    out = []
    seen = set()
    suffix = "." + domain.lower()
    for line in lines:
        s = line.strip().lower().rstrip(".")
        if not s:
            continue
        if s.startswith("*."):
            s = s[2:]
        if s in seen:
            continue
        if s != domain.lower() and not s.endswith(suffix):
            continue
        seen.add(s)
        out.append(s)
    return sorted(out)


def _crtsh_fallback(domain):
    """Enumerate subdomains from Certificate Transparency — no local tools needed."""
    try:
        from app.services.correlation.cert_transparency import get_cert_history
        cert = get_cert_history(domain)
    except Exception as e:
        return {"status": "error", "tool": "crt.sh", "message": str(e)}

    if cert.get("status") not in ("ok", "ok_degraded"):
        return {
            "status": "error",
            "tool": "crt.sh",
            "message": f"crt.sh unavailable ({cert.get('status')})",
        }

    subs = _clean(cert.get("subdomains", []), domain)
    return {
        "status": "ok",
        "tool": "crt.sh",
        "domain": domain,
        "subdomain_count": len(subs),
        "subdomains": subs,
        "note": (
            "subfinder not available — enumerated from Certificate Transparency "
            "only. Coverage is lower than subfinder's multi-source enumeration."
        ),
    }


def run_subfinder(domain, timeout=DEFAULT_TIMEOUT, use_all_sources=False):
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {"status": "error", "tool": "subfinder", "message": "empty domain"}

    binary = _find_binary(SUBFINDER_CANDIDATES, env_var="SUBFINDER_PATH")
    if not binary:
        result = _crtsh_fallback(domain)
        result["subfinder_status"] = "tool_not_found"
        return result

    cmd = [binary, "-d", domain, "-silent"]
    if use_all_sources:
        cmd.append("-all")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        # Partial output on timeout is still useful.
        partial = _clean((e.stdout or "").splitlines(), domain) if e.stdout else []
        if partial:
            return {
                "status": "ok",
                "tool": "subfinder",
                "domain": domain,
                "subdomain_count": len(partial),
                "subdomains": partial,
                "warning": f"subfinder timed out after {timeout}s; results are partial",
            }
        return {"status": "timeout", "tool": "subfinder", "timeout_seconds": timeout}
    except Exception as e:
        return {"status": "error", "tool": "subfinder", "message": str(e)}

    subdomains = _clean(proc.stdout.splitlines(), domain)

    # Non-zero exit with usable stdout = some sources failed, not total failure.
    if not subdomains and proc.returncode != 0:
        fallback = _crtsh_fallback(domain)
        fallback["subfinder_status"] = "error"
        fallback["subfinder_stderr"] = (proc.stderr or "").strip()[:500]
        return fallback

    result = {
        "status": "ok",
        "tool": "subfinder",
        "domain": domain,
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
    }
    if proc.returncode != 0:
        result["warning"] = (
            "subfinder exited non-zero (usually a source without an API key); "
            "results below are what it did return."
        )
        result["stderr"] = (proc.stderr or "").strip()[:500]
    return result