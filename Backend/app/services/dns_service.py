"""
DNS Service
-----------
Resolves A, MX, and NS records for a host.
"""

import dns.resolver


def get_dns_info(host):
    result = {"a_records": [], "mx_records": [], "ns_records": [], "error": None}
    try:
        try:
            result["a_records"] = [r.to_text() for r in dns.resolver.resolve(host, "A")]
        except Exception as e:
         result["a_error"] = str(e)
        try:
            result["mx_records"] = [r.to_text() for r in dns.resolver.resolve(host, "MX")]
        except Exception as e:
            result["mx_error"] = str(e)
        try:
            result["ns_records"] = [r.to_text() for r in dns.resolver.resolve(host, "NS")]
        except Exception as e:
            result["ns_error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result