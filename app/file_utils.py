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