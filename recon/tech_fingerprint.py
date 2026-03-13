import requests


def run_tech_fingerprint(target):

    print(f"\n[+] Fingerprinting {target}\n")

    try:

        r = requests.get(target, timeout=10)

        headers = r.headers
        html = r.text.lower()

        # Server detection
        if "server" in headers:
            print("[Server]", headers["server"])

        # CDN / WAF
        if "cloudflare" in headers.get("server", "").lower():
            print("[WAF] Cloudflare")

        if "akamai" in headers.get("server", "").lower():
            print("[CDN] Akamai")

        # Framework detection
        if "react" in html:
            print("[Framework] React")

        if "vue" in html:
            print("[Framework] Vue")

        if "angular" in html:
            print("[Framework] Angular")

        # Backend hints
        if "x-powered-by" in headers:
            print("[Backend]", headers["x-powered-by"])

        # CMS detection
        if "wp-content" in html:
            print("[CMS] WordPress")

        if "drupal" in html:
            print("[CMS] Drupal")

        if "shopify" in html:
            print("[CMS] Shopify")

        print("\n[+] Fingerprinting finished")

    except Exception as e:

        print("Error:", e)