import json

def load_database():
    with open("known_hashes.json", "r") as file:
        database = json.load(file)
    return database

def lookup_hash(database, hash_string):
    if hash_string in database:
        return database[hash_string]
    else:
        return None