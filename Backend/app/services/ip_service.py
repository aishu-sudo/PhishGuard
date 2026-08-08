import socket
import ipaddress
from ipwhois import IPWhois


def _resolve_all(host, port=443):
    """Return (ipv4_list, ipv6_list) using getaddrinfo — all records, deduped."""
    v4, v6 = [], []
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except Exception:
        return v4, v6

    for family, _type, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0]
        if family == socket.AF_INET:
            if addr not in v4:
                v4.append(addr)
        elif family == socket.AF_INET6:
            if addr not in v6:
                v6.append(addr)
    return v4, v6


def _rdap(ip):
    try:
        rdap = IPWhois(ip).lookup_rdap(depth=1)
        return {
            "asn": rdap.get("asn"),
            "hosting": rdap.get("asn_description"),
            "country": rdap.get("asn_country_code"),
        }, None
    except Exception as e:
        return {"asn": None, "hosting": None, "country": None}, str(e)


def get_ip_info(host):
    if not host:
        return {"error": "no host supplied"}

    host = host.strip().rstrip(".").lower()

    ipv4, ipv6 = _resolve_all(host)

    if not ipv4 and not ipv6:
        return {"error": f"DNS resolution failed for {host}", "host": host}

    primary = ipv4[0] if ipv4 else ipv6[0]

    try:
        is_private = ipaddress.ip_address(primary).is_private
    except ValueError:
        is_private = False

    result = {
        "host": host,
        "ip": primary,              # kept for backward compatibility
        "ipv4": ipv4,
        "ipv6": ipv6,
        "record_count": len(ipv4) + len(ipv6),
        "asn": None,
        "hosting": None,
        "country": None,
        "is_private": is_private,
    }

    if not is_private:
        enrich, err = _rdap(primary)
        result.update(enrich)
        if err:
            result["rdap_error"] = err

    return result