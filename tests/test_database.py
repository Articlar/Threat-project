from app.database import lookup_hash

def test_lookup_existing_hash():
    database = {
        "abc123": {
            "name": "Test Malware",
            "type": "malicious"
        }
    }

    result = lookup_hash(database, "abc123")

    assert result["name"] == "Test Malware"
    assert result["type"] == "malicious"


def test_lookup_unknown_hash():
    database = {
        "abc123": {
            "name": "Test Malware",
            "type": "malicious"
        }
    }

    result = lookup_hash(database, "doesnotexist")

    assert result is None