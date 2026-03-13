import sys
import os
from utils.banner import show_banner
from recon.js_crawler import run_js_scan
from recon.subdomain_bruteforce import run_subdomain_bruteforce
from recon.passive_subdomains import run_passive_subdomain_scan
from recon.tech_fingerprint import run_tech_fingerprint
from recon.deep_crawler import run_deep_crawler

R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
C  = "\033[96m"
W  = "\033[97m"
DIM = "\033[2m"
RESET = "\033[0m"

MENU = f"""
  {W}[1]{RESET} Endpoint Discovery
  {W}[2]{RESET} JavaScript Recon
  {W}[3]{RESET} API Detection
  {W}[4]{RESET} Parameter Fuzzing
  {W}[5]{RESET} Microservice Mapping
  {W}[6]{RESET} Subdomain Bruteforce
  {W}[7]{RESET} Passive Subdomain Scan
  {W}[8]{RESET} Deep Crawler
  {W}[9]{RESET} Tech Fingerprint

  {W}[A]{RESET} Run All Modules on Target
  {DIM}[0] Exit{RESET}
"""

def prompt_target(label="Target URL > ") -> str:
    while True:
        target = input(f"{G}{label}{RESET}").strip()
        if target:
            return target
        print(f"{R}[!] Target cannot be empty.{RESET}")

def run_all(target: str):
    print(f"\n{Y}[*] Running full scan on: {W}{target}{RESET}\n")
    steps = [
        ("JavaScript Recon",       lambda: run_js_scan(target)),
        ("Subdomain Bruteforce",   lambda: run_subdomain_bruteforce(target)),
        ("Passive Subdomain Scan", lambda: run_passive_subdomain_scan(target)),
        ("Deep Crawler",           lambda: run_deep_crawler(target)),
        ("Tech Fingerprint",       lambda: run_tech_fingerprint(target)),
    ]
    for name, fn in steps:
        print(f"{C}[>] {name}...{RESET}")
        try:
            fn()
        except Exception as e:
            print(f"{R}[!] {name} failed: {e}{RESET}")
    print(f"\n{G}[✓] Full scan complete.{RESET}")

def start_cli():
    show_banner()

    ACTIONS = {
        "1": ("Endpoint Discovery",    lambda: print(f"{Y}[!] Module not implemented yet.{RESET}")),
        "2": ("JavaScript Recon",      lambda: run_js_scan(prompt_target("Target URL > "))),
        "3": ("API Detection",         lambda: print(f"{Y}[!] Module not implemented yet.{RESET}")),
        "4": ("Parameter Fuzzing",     lambda: print(f"{Y}[!] Module not implemented yet.{RESET}")),
        "5": ("Microservice Mapping",  lambda: print(f"{Y}[!] Module not implemented yet.{RESET}")),
        "6": ("Subdomain Bruteforce",  lambda: run_subdomain_bruteforce(prompt_target("Target domain > "))),
        "7": ("Passive Subdomain Scan",lambda: run_passive_subdomain_scan(prompt_target("Target domain > "))),
        "8": ("Deep Crawler",          lambda: run_deep_crawler(prompt_target("Target URL > "))),
        "9": ("Tech Fingerprint",      lambda: run_tech_fingerprint(prompt_target("Target URL > "))),
        "a": ("Run All Modules",       lambda: run_all(prompt_target("Target > "))),
    }

    while True:
        print(MENU)
        try:
            option = input(f"{W}prothos{R}>{RESET} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{R}[!] Interrupted. Exiting Prothos...{RESET}")
            sys.exit(0)

        if option == "0":
            print(f"\n{DIM}Exiting Prothos...{RESET}\n")
            break

        if option in ACTIONS:
            name, fn = ACTIONS[option]
            print(f"\n{C}[*] Starting: {name}{RESET}")
            try:
                fn()
            except KeyboardInterrupt:
                print(f"\n{Y}[!] Module interrupted. Back to menu.{RESET}")
            except Exception as e:
                print(f"{R}[!] Unexpected error in '{name}': {e}{RESET}")
        else:
            print(f"{R}[!] Invalid option '{option}'. Try again.{RESET}")