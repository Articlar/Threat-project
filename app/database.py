import json
from pathlib import Path

def load_database():
    project_root = Path(__file__).parent.parent
    json_path = project_root / "known_hashes.json"
    with open(json_path, "r") as file:
        database = json.load(file)
    return database

def lookup_hash(database, hash_string):
    if hash_string in database:
        return database[hash_string]
    else:
        return None