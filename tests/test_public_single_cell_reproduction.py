# SPDX-License-Identifier: Apache-2.0
"""Offline lock consistency tests. CI separately builds/runs the actual container."""
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "examples/public-single-cell"
SPEC = importlib.util.spec_from_file_location("reproduction_checks", HERE / "check_reproduction.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ReproductionProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads((HERE / "reproduction-profile.json").read_text())
        self.lock = (HERE / "requirements-linux-cp312.lock").read_text()

    def test_checked_in_profile_and_lock_match(self):
        self.assertEqual(len(CHECK.validate_profile(self.profile, self.lock)), 5)

    def test_duplicate_package_is_rejected(self):
        self.profile["packages"].append(copy.deepcopy(self.profile["packages"][0]))
        with self.assertRaisesRegex(CHECK.ReproductionError, "PACKAGE_NAME"):
            CHECK.validate_profile(self.profile, self.lock)

    def test_lock_cannot_add_a_resolver_option_or_unpinned_package(self):
        for extra in ("\n--extra-index-url https://example.invalid", "\ncryptography", "\npip==26.2.1"):
            with self.subTest(extra=extra), self.assertRaisesRegex(CHECK.ReproductionError, "LOCK_PROFILE_MISMATCH"):
                CHECK.validate_profile(self.profile, self.lock + extra)

    def test_missing_lock_hash_is_rejected(self):
        line = self.lock.splitlines()[-1]
        with self.assertRaises(CHECK.ReproductionError):
            CHECK.validate_profile(self.profile, self.lock.replace(line, line.split(" --hash")[0]))

    def test_mutable_image_or_unreviewed_platform_is_rejected(self):
        for key, value in (("base_image", "python:3.12-slim"), ("platform", "linux/arm64")):
            body = copy.deepcopy(self.profile)
            body[key] = value
            with self.subTest(key=key), self.assertRaises(CHECK.ReproductionError):
                CHECK.validate_profile(body, self.lock)

    def test_filename_traversal_bad_size_and_bad_hash_are_rejected(self):
        for key, value in (("filename", "../x.whl"), ("bytes", True), ("bytes", 0), ("sha256", "main")):
            body = copy.deepcopy(self.profile)
            body["packages"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(CHECK.ReproductionError):
                CHECK.validate_profile(body, self.lock)

    def test_dockerfile_matches_profile_and_requires_hashes(self):
        text = (HERE / "Dockerfile").read_text()
        self.assertIn("FROM " + self.profile["base_image"] + "\n", text)
        self.assertIn("--only-binary=:all: --require-hashes", text)
        self.assertIn("USER 65532:65532", text)
        self.assertNotIn("COPY . ", text)

    def test_versions_preserve_the_original_observed_environment(self):
        observed = json.loads((HERE / "observed-run.json").read_text())
        packages = {p["name"]: p["version"] for p in self.profile["packages"]}
        for name, version in observed["verification"]["packages"].items():
            self.assertEqual(packages[name], version)
        self.assertEqual(self.profile["python"], observed["verification"]["python"])

    def test_environment_check_rejects_other_python_without_skip(self):
        with patch.object(CHECK.platform, "python_version", return_value="3.13.5"), self.assertRaisesRegex(CHECK.ReproductionError, "PYTHON_MISMATCH"):
            CHECK.check_environment(self.profile)

    def test_installed_version_mismatch_is_not_accepted(self):
        with patch.object(CHECK, "version", return_value="0.0.0"), self.assertRaisesRegex(CHECK.ReproductionError, "INSTALLED_VERSION_MISMATCH"):
            CHECK.check_installed(self.profile["packages"])

    def test_readme_historical_checkout_is_the_reachable_reference(self):
        text = (HERE / "README.md").read_text()
        self.assertIn("git checkout " + self.profile["historical_reproduction_commit"], text)
        self.assertNotIn("git checkout 160e39b", text)


class WheelBytesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "fixture-1.0-py3-none-any.whl"
        self.path.write_bytes(b"synthetic fixture, not a Python wheel")
        self.items = [{"filename": self.path.name, "bytes": self.path.stat().st_size,
                       "sha256": hashlib.sha256(self.path.read_bytes()).hexdigest()}]

    def test_exact_recorded_bytes_pass(self):
        CHECK.check_wheelhouse(self.root, self.items)

    def test_same_size_changed_bytes_fail(self):
        b = bytearray(self.path.read_bytes())
        b[0] ^= 1
        self.path.write_bytes(b)
        with self.assertRaisesRegex(CHECK.ReproductionError, "WHEEL_HASH_MISMATCH"):
            CHECK.check_wheelhouse(self.root, self.items)

    def test_missing_and_extra_members_fail(self):
        extra = self.root / "extra.whl"
        extra.write_bytes(b"x")
        with self.assertRaisesRegex(CHECK.ReproductionError, "WHEEL_MEMBERSHIP"):
            CHECK.check_wheelhouse(self.root, self.items)
        extra.unlink()
        self.path.unlink()
        with self.assertRaisesRegex(CHECK.ReproductionError, "WHEEL_MEMBERSHIP"):
            CHECK.check_wheelhouse(self.root, self.items)

    def test_wrong_size_fails(self):
        self.path.write_bytes(b"shorter")
        with self.assertRaisesRegex(CHECK.ReproductionError, "WHEEL_BYTE_COUNT"):
            CHECK.check_wheelhouse(self.root, self.items)

    def test_symlink_is_not_followed(self):
        target = self.root / "target"
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(CHECK.ReproductionError):
            CHECK.check_wheelhouse(self.root, self.items)


if __name__ == "__main__":
    unittest.main()
