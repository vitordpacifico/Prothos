import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin


visited = set()


def extract_endpoints(text):

    pattern = r'["\'](\/api\/[a-zA-Z0-9\/\-_]+)["\']'

    return re.findall(pattern, text)


def crawl(url, depth=2):

    if depth == 0:
        return

    if url in visited:
        return

    visited.add(url)

    print(f"[+] Crawling {url}")

    try:

        r = requests.get(url, timeout=10)

        soup = BeautifulSoup(r.text, "html.parser")

        endpoints = extract_endpoints(r.text)

        for ep in endpoints:
            print(f"[API] {ep}")

        for link in soup.find_all("a", href=True):

            new_url = urljoin(url, link["href"])

            crawl(new_url, depth - 1)

    except:
        pass


def run_deep_crawler(target):

    print(f"\n[+] Starting deep crawl on {target}\n")

    crawl(target, depth=3)