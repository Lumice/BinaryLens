#!/usr/bin/env python3
"""
BinaryLens Release Packager
Generates a clean, validated distribution ZIP archive for IDA Pro 8.x and 9.x.
Compatible with IDA 9 HCLI / Plugin Manager and manual drop-in installation.
"""

import os
import json
import zipfile

def build_release():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dist_dir = os.path.join(root_dir, "dist")
    os.makedirs(dist_dir, exist_ok=True)

    manifest_path = os.path.join(root_dir, "ida-plugin.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    version = manifest.get("plugin", {}).get("version", "1.2.0")
    archive_name = f"BinaryLens-v{version}.zip"
    archive_path = os.path.join(dist_dir, archive_name)

    source_plugin = os.path.join(root_dir, "python", "binarylens.py")
    readme_path = os.path.join(root_dir, "README.md")
    license_path = os.path.join(root_dir, "LICENSE")

    required = [manifest_path, source_plugin, readme_path, license_path]
    missing = [path for path in required if not os.path.isfile(path)]
    if missing:
        raise FileNotFoundError(f"Required release files missing: {missing}")

    entry_point = manifest.get("plugin", {}).get("entryPoint", "binarylens.py")
    files_to_pack = [
        (manifest_path, "ida-plugin.json"),
        (source_plugin, entry_point),
        (readme_path, "README.md"),
        (license_path, "LICENSE"),
    ]

    print(f"Building BinaryLens v{version} release package...")
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for src, arcname in files_to_pack:
            zf.write(src, arcname)
            print(f"  [+] Added: {arcname}")

    size_kb = os.path.getsize(archive_path) / 1024.0
    print(f"\nRelease package created successfully:")
    print(f"  Path: {archive_path}")
    print(f"  Size: {size_kb:.2f} KB\n")

    print("Contents of archive:")
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            print(f"  - {info.filename} ({info.file_size} bytes)")

if __name__ == "__main__":
    build_release()
