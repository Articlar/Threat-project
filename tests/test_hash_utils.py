from app.hash_utils import hash_type


def test_md5():
    assert hash_type("44d88612fea8a8f36de82e1278abb02f") == "MD5"


def test_sha1():
    assert hash_type("356a192b7913b04c54574d18c28d46e6395428ab") == "SHA1"


def test_sha256():
    assert hash_type(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    ) == "SHA256"


def test_invalid_characters():
    assert hash_type(
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    ) == "Not a hash"


def test_invalid_length():
    assert hash_type("abcdef1234567890") == "Not a hash"