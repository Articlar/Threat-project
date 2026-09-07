from app.file_utils import (
    calculate_hashes,
    get_file_metadata,
    analyze_file_type,
    detect_file_type,
    check_file_type_mismatch
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

def test_get_file_metadata(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")

    result = get_file_metadata(test_file)

    assert result is not None
    assert result["file_name"] == "test.txt"
    assert result["file_extension"] == ".txt"
    assert result["file_size"] == 11


def test_get_file_metadata_file_not_found():
    result = get_file_metadata("does_not_exist.txt")

    assert result is None

def test_analyze_file_type(tmp_path):
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"test")

    result = analyze_file_type(test_file)

    assert result is not None
    assert result["extension"] == ".exe"
    assert result["is_executable"] is True
    assert result["is_script"] is False


def test_analyze_file_type_script(tmp_path):
    test_file = tmp_path / "test.ps1"
    test_file.write_text("Write-Host 'test'")

    result = analyze_file_type(test_file)

    assert result["is_executable"] is False
    assert result["is_script"] is True

def test_detect_file_type(tmp_path):
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 20)

    result = detect_file_type(test_file)

    assert result == "PE"


def test_detect_png(tmp_path):
    test_file = tmp_path / "test.png"
    test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)

    result = detect_file_type(test_file)

    assert result == "PNG"


def test_detect_unknown_file_type(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"random data")

    result = detect_file_type(test_file)

    assert result == "UNKNOWN"

def test_check_file_type_mismatch(tmp_path):
    test_file = tmp_path / "test.jpg"
    test_file.write_bytes(b"MZ" + b"\x00" * 20)

    result = check_file_type_mismatch(test_file)

    assert result is True


def test_check_file_type_matches(tmp_path):
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 20)

    result = check_file_type_mismatch(test_file)

    assert result is False