#!/usr/bin/env python3
import sys
import re
import hashlib
import urllib.request
from pathlib import Path
from typing import Dict, Optional
import tempfile


VERSION_RE = re.compile(r"v\d+\.\d+\.\d+")


class HashComputationError(Exception):
    pass


def compute_hash(url: str) -> str:
    try:
        with tempfile.NamedTemporaryFile() as tmp_file:
            urllib.request.urlretrieve(url, tmp_file.name)

            sha256_hash = hashlib.sha256()
            with open(tmp_file.name, "rb") as f:
                sha256_hash.update(f.read())
            return sha256_hash.hexdigest()
    except Exception as e:
        raise HashComputationError(f"failed to compute hash for {url}") from e


def update_metadata_file(file_path: Path, new_version: str) -> None:
    if not file_path.exists():
        print(f"error: file {file_path} not found")
        sys.exit(1)

    content = file_path.read_text()

    urls_to_update: Dict[str, str] = {}
    for line in content.splitlines():
        if "url:" not in line:
            continue

        url_match = re.search(r"url:\s*(.*)", line)
        if not url_match:
            continue

        old_url = url_match.group(1).strip()
        new_url = re.sub(VERSION_RE, new_version, old_url)
        if old_url == new_url:
            continue

        urls_to_update[old_url] = new_url

    new_hashes: Dict[str, str] = {}
    print("calculating new hashes...")
    for new_url in urls_to_update.values():
        print(f"fetching: {new_url}")
        try:
            new_hashes[new_url] = compute_hash(new_url)
        except HashComputationError as e:
            print(f"warning: {str(e)}")
            new_hashes[new_url] = "XXXX"

    updated_lines = []
    current_url = None

    for line in content.splitlines():
        updated_line = line

        if "url:" in line:
            url_match = re.search(r"url:\s*(.*)", line)
            if not url_match:
                updated_lines.append(updated_line)
                continue

            old_url = url_match.group(1).strip()
            current_url = re.sub(VERSION_RE, new_version, old_url)
            updated_line = re.sub(re.escape(old_url), current_url, line)

        elif "sha256:" in line and current_url and current_url in new_hashes:
            updated_line = re.sub(
                r"sha256:\s*\S+", f"sha256: {new_hashes[current_url]}", line
            )
            current_url = None

        updated_lines.append(updated_line)

    file_path.write_text("\n".join(updated_lines) + "\n")
    print(f"{file_path} updated to {new_version}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python update_version.py <version>")
        sys.exit(1)

    new_version = sys.argv[1]
    if not bool(VERSION_RE.match(new_version)):
        print("version must be in the format vX.X.X (e.g., v1.2.3)")
        sys.exit(1)

    metadata_file = Path("net.casimirlab.frigoligo.yml")
    update_metadata_file(metadata_file, new_version)
