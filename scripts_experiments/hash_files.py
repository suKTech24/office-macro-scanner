"""Print MD5, SHA1 and SHA256 hashes of files
https://docs.python.org/3/library/hashlib.html
"""
import hashlib
import sys
from pathlib import Path

ALGORITHMS = ("md5", "sha1", "sha256")
# Size of chunks to read from files when hashing at a time
# 65,536 bytes or 64 KiB
# Reading in chunks helps with large files and 
# avoids loading the entire file into memory at once   
CHUNK_SIZE = 64 * 1024


def hash_file(path: Path) -> dict[str, str]:
    hashers = {name: hashlib.new(name) for name in ALGORITHMS}

    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            for h in hashers.values():
                h.update(chunk)

    return {name: h.hexdigest().upper() for name, h in hashers.items()}


def main(patterns: list[str]) -> None:
    for pattern in patterns:
        
        matches = sorted(Path().glob(pattern)) or [Path(pattern)]

        for path in matches:
            print(path)
            for name, digest in hash_file(path).items():
                print(f"  {name.upper():<7} {digest}")
            print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: py scripts/hash_files.py <file-or-glob> [...]")
    main(sys.argv[1:])
