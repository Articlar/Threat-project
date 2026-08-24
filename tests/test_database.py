from app.database import load_database, lookup_hash

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

def test_load_database():
    database = load_database()

    assert isinstance(database, dict)
    assert "44d88612fea8a8f36de82e1278abb02f" in database