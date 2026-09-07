import hashlib
from pathlib import Path

def calculate_hashes(file_path):
    path = Path(file_path)

    if not path.is_file():
        return None

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    # Reads file in binary, reads it by chunks for heavy files
    with open(path, "rb") as file:
        chunk = file.read(8192)

        while chunk:
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

            chunk = file.read(8192)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }

def get_file_metadata(file_path):
    path = Path(file_path)

    if not path.is_file():
        return None

    return {
        "file_name": path.name,
        "file_extension": path.suffix.lower(),
        "file_size": path.stat().st_size
    }

def analyze_file_type(file_path):
    path = Path(file_path)

    if not path.is_file():
        return None

    extension = path.suffix.lower()

    executable_extensions = {
        ".exe",
        ".dll",
        ".sys",
        ".scr",
        ".com",
        ".bat",
        ".cmd",
        ".msi"
    }

    script_extensions = {
        ".ps1",
        ".vbs",
        ".js",
        ".py",
        ".hta"
    }

    return {
        "extension": extension,
        "is_executable": extension in executable_extensions,
        "is_script": extension in script_extensions
    }

def detect_file_type(file_path):
    path = Path(file_path)

    if not path.is_file():
        return None

    with open(path, "rb") as file:
        header = file.read(16)

    if header[:2] == b"MZ":
        return "PE"

    if header[:4] == b"\x7fELF":
        return "ELF"

    if header[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"

    if header[:3] == b"\xff\xd8\xff":
        return "JPEG"

    if header[:4] == b"%PDF":
        return "PDF"

    if header[:4] == b"PK\x03\x04":
        return "ZIP"

    return "UNKNOWN"

def check_file_type_mismatch(file_path):
    path = Path(file_path)

    if not path.is_file():
        return None

    extension = path.suffix.lower()
    detected_type = detect_file_type(file_path)

    expected_extensions = {
        "PE": [".exe", ".dll", ".sys", ".scr", ".com"],
        "ELF": [".elf"],
        "PNG": [".png"],
        "JPEG": [".jpg", ".jpeg"],
        "PDF": [".pdf"],
        "ZIP": [".zip"]
    }

    if detected_type not in expected_extensions:
        return False

    return extension not in expected_extensions[detected_type]