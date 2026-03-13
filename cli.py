from utils.banner import show_banner
from recon.js_crawler import run_js_scan
from recon.subdomain_bruteforce import run_subdomain_bruteforce
from recon.passive_subdomains import run_passive_subdomain_scan
from recon.tech_fingerprint import run_tech_fingerprint
from recon.deep_crawler import run_deep_crawler

def start_cli():

    show_banner()

    while True:

        print("\n[1] Endpoint Discovery")
        print("[2] JavaScript Recon")
        print("[3] API Detection")
        print("[4] Parameter Fuzzing")
        print("[5] Microservice Mapping")
        print("[6] Subdomain Bruteforce")
        print("[7] Passive Subdomain Scan")
        print("[8] Deep Crawler")
        print("[9] Tech Fingerprint")
        print("[0] Exit")

        option = input("\nSelect option > ")

        if option == "1":
            print("Running Endpoint Discovery...")

        elif option == "2":
            target = input("Enter target URL: ")
            run_js_scan(target)

        elif option == "3":
            print("Running API Detection...")

        elif option == "4":
            print("Running Parameter Fuzzer...")

        elif option == "5":
            print("Running Microservice Mapper...")

        elif option == "6":
            target = input("Target domain > ")
            run_subdomain_bruteforce(target)

        elif option == "7":
            target = input("Target domain > ")
            run_passive_subdomain_scan(target)

        elif option == "8":
            target = input("Target URL > ")
            run_deep_crawler(target)

        elif option == "9":
            target = input("Target URL > ")
            run_tech_fingerprint(target)

        elif option == "0":
            print("Exiting Prothos...")
            break

        else:
            print("Invalid option.")