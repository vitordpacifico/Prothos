from subbrute import run
from engines.subbrute_engine import run

def run_subdomain_bruteforce(domain):

    print(f"[+] Starting subdomain bruteforce on {domain}\n")

    for result in run(domain):

        hostname, record_type, record = result

        print(f"[+] {hostname} -> {record}")