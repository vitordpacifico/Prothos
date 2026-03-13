import requests

def run_passive_subdomain_scan(domain):

    print(f"\n[+] Searching certificate logs for {domain}\n")

    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:

        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            print("Failed to query certificate logs")
            return

        data = r.json()

        subdomains = set()

        for entry in data:

            name = entry["name_value"]

            for sub in name.split("\n"):
                if domain in sub:
                    subdomains.add(sub.strip())

        print(f"[+] Found {len(subdomains)} subdomains\n")

        for sub in sorted(subdomains):
            print(sub)

    except Exception as e:
        print("Error:", e)