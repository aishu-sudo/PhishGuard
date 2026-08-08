from app.services.correlation.cert_transparency import get_cert_history
from app.services.correlation.reverse_ip import get_shared_hosts
import json

def main():
    domain = "banglayielts.com"
    ip = "104.21.92.44"
    hosting = "CLOUDFLARENET - Cloudflare, Inc., US"

    print("=== Certificate Transparency (crt.sh) ===")
    cert_result = get_cert_history(domain)
    print(json.dumps(cert_result, indent=2))

    print("\n=== Reverse IP / Shared Hosting ===")
    host_result = get_shared_hosts(ip, hosting_provider=hosting)
    print(json.dumps(host_result, indent=2))

if __name__ == "__main__":
    main()