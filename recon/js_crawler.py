import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup

def run_js_scan(target):

    print(f"[+] Crawling {target}")

    try:
        r = requests.get(target, timeout=10)
    except Exception as e:
        print(f"[-] Error: {e}")
        return

    soup = BeautifulSoup(r.text, "html.parser")

    scripts = []

    for script in soup.find_all("script"):

        src = script.get("src")

        if src:
            full_url = urljoin(target, src)
            scripts.append(full_url)

    print(f"[+] Found {len(scripts)} JS files")

    endpoints = set()

    for js in scripts:

        try:
            js_req = requests.get(js, timeout=10)
        except:
            continue

        matches = re.findall(r'\/api\/[a-zA-Z0-9_\-\/]+', js_req.text)

        for m in matches:
            endpoints.add(m)

    print("\n[+] Endpoints discovered:")

    for ep in endpoints:
        print(ep)