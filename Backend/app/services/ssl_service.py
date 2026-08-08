import socket
import ssl
from datetime import datetime


def get_ssl_info(host, port=443, timeout=5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in cert.get("issuer", []))

        return {
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "valid_from": str(not_before),
            "valid_until": str(not_after),
            "cert_age_days": (datetime.now() - not_before).days,
            "is_lets_encrypt": "let's encrypt" in str(issuer).lower(),
        }
    except Exception as e:
        return {"error": str(e)}