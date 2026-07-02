import hash_utils
import json

def main():
    with open("known_hashes.json", "r") as file:
        database = json.load(file)
    print("Hello Threat and Hash checks: ")
    ins = input("Input hash here:\n")

    if ins in database:
        data = database[ins]
        print("Found in local database")
        print("NAME: ", data["name"])
        print("Status:", data["type"])
        print("Description:", data["description"])
    else:
        print("Hash not found in local database")
    
    print("\nHash Analysis:")
    print("Input: ", ins) 
    print("Type: ", hash_utils.hash_type(ins))
    return 

if __name__ == "__main__":
    main()