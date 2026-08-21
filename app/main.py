import hash_utils
import json

def main():
    # Opening the locally saved known hashes
    with open("known_hashes.json", "r") as file:
        database = json.load(file)
    print("Hello Threat and Hash checks: ")

    while True:
        user_input = input("Input hash here ('exit' to stop):\n")

        if user_input == "exit":
            break
        hash_result = hash_utils.hash_type(user_input)

        # Input validation
        if hash_result == "Not a hash":
            print("Try again, not a valid hash")
            continue
        elif user_input in database:
            data = database[user_input]
            print("Found in local database")
            print("NAME: ", data["name"])
            print("Status:", data["type"])
            print("Description:", data["description"])
        else:
            print("Hash not found in local database")
        print("\nHash Analysis:")
        print("Input: ", user_input) 
        print("Type: ", hash_result)

    return 

if __name__ == "__main__":
    main()