from urllib.parse import urlparse

from app.services.dns_service import get_dns_info
from app.services.ip_service import get_ip_info
from app.services.redirect_service import get_redirect_chain
from app.services.safe_browsing import check_safe_browsing
from app.services.ssl_service import get_ssl_info
from app.services.whois_service import get_whois_info
from app.services.virustotal_service import check_virustotal
from app.config import VT_API_KEY

def main():
    url = "https://www.banglayielts.com/"
    host = urlparse(url).hostname  # e.g. "example.com"

    print("=== WHOIS ===")
    print(get_whois_info(host))

    print("\n=== DNS ===")
    print(get_dns_info(host))

    print("\n=== SSL ===")
    print(get_ssl_info(host))

    print("\n=== Redirect chain ===")
    print(get_redirect_chain(url))

    print("\n=== IP ===")
    print(get_ip_info(host))

    print("\n=== Safe Browsing ===")
    print(check_safe_browsing(url))

    print("\n=== VirusTotal ===")
    print(check_virustotal(url, api_key=VT_API_KEY))

if __name__ == "__main__":
    main()