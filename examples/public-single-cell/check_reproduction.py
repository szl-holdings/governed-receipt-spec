#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline checks for reviewed package artifacts; not a signature or science verdict."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
from importlib.metadata import version
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROFILE = HERE / "reproduction-profile.json"
LOCK = HERE / "requirements-linux-cp312.lock"
NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ReproductionError(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ReproductionError(code)


def validate_profile(profile: dict[str, Any], lock: str) -> list[dict[str, Any]]:
    require(profile.get("schema") == "public-single-cell-reproduction-profile/v1", "PROFILE_SCHEMA")
    require(profile.get("platform") == "linux/amd64" and profile.get("python") == "3.12.14"
            and profile.get("minimum_glibc") == "2.34", "UNREVIEWED_PLATFORM")
    image = profile.get("base_image")
    require(isinstance(image, str) and re.fullmatch(r"python:3\.12\.14-slim@sha256:[0-9a-f]{64}", image) is not None,
            "IMAGE_DIGEST_REQUIRED")
    packages = profile.get("packages")
    require(isinstance(packages, list) and 1 <= len(packages) <= 10, "PACKAGE_BUDGET")
    names, filenames = set(), set()
    for item in packages:
        require(isinstance(item, dict), "PACKAGE_OBJECT")
        name, ver, filename, digest, size = (item.get(k) for k in ("name", "version", "filename", "sha256", "bytes"))
        require(isinstance(name, str) and NAME.fullmatch(name) is not None and name not in names, "PACKAGE_NAME")
        require(isinstance(ver, str) and VERSION.fullmatch(ver) is not None, "EXACT_VERSION_REQUIRED")
        require(isinstance(filename, str) and re.fullmatch(r"[A-Za-z0-9_.-]+\.whl", filename) is not None
                and filename.startswith(name.replace("-", "_") + "-" + ver + "-")
                and filename not in filenames, "WHEEL_FILENAME")
        require(isinstance(digest, str) and HEX64.fullmatch(digest) is not None, "WHEEL_DIGEST")
        require(type(size) is int and 0 < size <= 64 * 1024 * 1024, "WHEEL_SIZE")
        names.add(name)
        filenames.add(filename)
    expected = [f"{p['name']}=={p['version']} --hash=sha256:{p['sha256']}" for p in sorted(packages, key=lambda p: p["name"])]
    actual = [line.strip() for line in lock.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    require(actual == expected, "LOCK_PROFILE_MISMATCH")
    return packages


def check_wheelhouse(directory: Path, packages: list[dict[str, Any]]) -> None:
    require(directory.is_dir() and not directory.is_symlink(), "WHEEL_DIRECTORY")
    require({p.name for p in directory.iterdir()} == {p["filename"] for p in packages}, "WHEEL_MEMBERSHIP")
    for item in packages:
        path = directory / item["filename"]
        require(path.is_file() and not path.is_symlink(), "WHEEL_NOT_REGULAR")
        require(path.stat().st_size == item["bytes"], "WHEEL_BYTE_COUNT")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        require(digest.hexdigest() == item["sha256"], "WHEEL_HASH_MISMATCH")


def check_environment(profile: dict[str, Any]) -> None:
    require(platform.python_implementation() == "CPython" and platform.python_version() == profile["python"], "PYTHON_MISMATCH")
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "PLATFORM_MISMATCH")
    libc, ver = platform.libc_ver()
    require(libc == "glibc" and re.fullmatch(r"[0-9]+\.[0-9]+", ver) is not None, "GLIBC_REQUIRED")
    require(tuple(map(int, ver.split("."))) >= (2, 34), "GLIBC_TOO_OLD")


def check_installed(packages: list[dict[str, Any]]) -> None:
    for item in packages:
        require(version(item["name"]) == item["version"], "INSTALLED_VERSION_MISMATCH")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--environment", action="store_true")
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args()
    try:
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        packages = validate_profile(profile, LOCK.read_text(encoding="utf-8"))
        if args.wheelhouse:
            check_wheelhouse(args.wheelhouse, packages)
        if args.environment:
            check_environment(profile)
        if args.installed:
            check_installed(packages)
        print(json.dumps({"status": "PASS", "scope": "dependency artifact consistency only", "packages": len(packages),
                          "profile_sha256": hashlib.sha256(PROFILE.read_bytes()).hexdigest(),
                          "lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
                          "wheel_bytes_checked": args.wheelhouse is not None,
                          "environment_checked": args.environment, "installed_versions_checked": args.installed,
                          "signature_verified": False, "biological_validation": False}))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
