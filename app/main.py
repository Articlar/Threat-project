import hash_utils
import database

def main():
    # Opening the locally saved known hashes
    known_hashes = database.load_database()
    print("Hello Threat and Hash checks: ")

    while True:
        user_input = input("Input hash here ('exit' to stop):\n")

        if user_input == "exit":
            break
        hash_result = hash_utils.hash_type(user_input)

        # Input validation
        if user_input == "Not a hash":
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

    return 

if __name__ == "__main__":
    main()