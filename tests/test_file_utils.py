from app.file_utils import (
    calculate_hashes
)

def test_calculate_hashes(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")

    result = calculate_hashes(test_file)

    assert result["md5"] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
    assert result["sha1"] == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    assert result["sha256"] == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

def test_calculate_hashes_file_not_found():
    result = calculate_hashes("does_not_exist.txt")

    assert result is None
    