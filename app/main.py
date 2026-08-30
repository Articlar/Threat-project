import hash_utils
import database
import url_utils
import json

def main():
    # Opening the locally saved known hashes
    known_hashes = database.load_database()

    while True:
        print("================= Threat and Hash Checks ================\n")
        print("1. HASH ANALYSIS")
        print("2. DOMAIN ANALYSIS")
        print("3. IP ANALYSIS")
        print("999. EXIT")
        choice = input("Type a number: ")

        # Hash Analysis Option
        if choice == "1":
            print("======== Hash Analysis ========")
            user_input = input("Input hash here: ")
            hash_result = hash_utils.hash_type(user_input)
            # Input validation
            if hash_result == "Not a hash":
                print("Try again, not a valid hash")
                continue
            data = database.lookup_hash(known_hashes, user_input)

            result = {
                "hash": user_input,
                "hash_type": hash_result,
                "found_in_local_database": data is not None,
                "name": None,
                "status": None,
                "description": None
            }

            if data is not None:
                result["name"] = data["name"]
                result["status"] = data["type"]
                result["description"] = data["description"]
            print(json.dumps(result, indent=4))

        # Domain Analysis Option
        elif choice == "2":
            print("======== Domain Analysis ========")
            user_input = input("Input URL here: ")

            # Gets hostname from user input
            domain = url_utils.extract_domain(user_input)

            if domain is None:
                print("Could not extract a domain")
                continue

            if url_utils.is_ip_address(domain):
                print("IP address. Use IP Analysis instead")
                continue

            is_domain = url_utils.check_domain(domain)
            if not is_domain:
                print("Invalid domain")
                continue

            # DNS resolution
            ip_address = url_utils.resolve_domain(domain)
            if ip_address is None:
                print("Domain does not resolve")
                continue

            https_status, http_status = url_utils.get_http_info(domain)
            certificate_info = url_utils.get_certificate_info(domain)
            heuristics = url_utils.analyze_domain(domain)
            url_analysis = url_utils.analyze_url(user_input)

            result = {
                "domain": domain,
                "valid_domain": True,
                "ip_address": ip_address,
                "https_status": https_status,
                "http_status": http_status,
                "certificate": certificate_info,
                "heuristics": heuristics,
                "url_analysis": url_analysis
            }

            print("\nDomain Analysis Result:")
            print(json.dumps(result, indent=4))

        elif choice == "3":
            print("======== IP Analysis ========")

            user_input = input("Input IP address here: ")

            if not url_utils.is_ip_address(user_input):
                print("Invalid IP Address")
                continue
            ip_version = url_utils.get_ip_version(user_input)

            result = {
                "ip_address": user_input,
                "valid_ip": True,
                "version": ip_version
            }

            print("\nIP Analysis:")
            print(json.dumps(result, indent=4))

        elif choice == "999":
            break

        else:
            print("Invalid choice, please try again")
    return 

if __name__ == "__main__":
    main()