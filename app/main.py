import hash_utils
import database
import url_utils

def main():
    # Opening the locally saved known hashes
    known_hashes = database.load_database()

    while True:
        print("================= Threat and Hash Checks ================\n")
        print("1. HASH ANALYSIS")
        print("2. DOMAIN ANALYSIS")
        print("3. EXIT")
        choice = input("Type a number: ")

        if choice == "1":
            print("======== Hash Analysis ========")
            user_input = input("Input hash here: ")
            hash_result = hash_utils.hash_type(user_input)
            # Input validation
            if hash_result == "Not a hash":
                print("Try again, not a valid hash")
                continue
            data = database.lookup_hash(known_hashes, user_input)

            if data is not None:
                print(("========================================="))
                print("\nFound in local known_hashes")
                print("NAME:", data["name"])
                print("Status:", data["type"])
                print("Description:", data["description"])
            else:
                print("=========================================")
                print("\nHash not found in local known_hashes")
                
                print("Hash Analysis:")
                print("Input: ", user_input) 
                print("Type: ", hash_result)
        elif choice == "2":
            print("======== Domain Analysis ========")
            user_input = input("Input URL here: ")
            # Checks for https:// or http
            domain = url_utils.extract_domain(user_input)

            if domain is None:
                print("Could not extract a domain")
                continue
            
            is_domain = url_utils.check_domain(user_input)
            if not is_domain:
                print("Invalid domain")
                continue

            ip_address = url_utils.resolve_domain(user_input)
            if ip_address is None:
                print("Domain does not resolve")
                continue
            https_status, http_status = url_utils.get_http_info(user_input)
            result = {
                "domain": user_input,
                "valid_domain": True,
                "ip_address": ip_address,
                "https_status": https_status,
                "http_status": http_status
            }
            print(result)

        elif choice == "3":
            break

        else:
            print("Invalid choice, please try again")
    return 

if __name__ == "__main__":
    main()