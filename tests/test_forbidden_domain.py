"""Exercise the workflow shell's scan outcomes and same-line guard policy."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/forbidden-domain.yml"


def scan_script():
    text = WORKFLOW.read_text(encoding="utf-8")
    step = text.split("      - name: Scan for forbidden domain references\n", 1)[1]
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


class ForbiddenDomainTests(unittest.TestCase):
    def run_scan(self, scanner_status=None, output="", files=None):
        bash = shutil.which("bash")
        if os.name == "nt":
            git_bash = Path("C:/Program Files/Git/bin/bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        self.assertIsNotNone(bash, "workflow regression tests require bash")
        # Stub only the scanner process, while executing the actual workflow shell.
        stub = ""
        if scanner_status is not None:
            stub = "rg() { printf '%s' \"$SCAN_OUTPUT\"; return \"$SCAN_STATUS\"; }\n"
        env = {**os.environ, "SCAN_STATUS": str(scanner_status), "SCAN_OUTPUT": output}
        if scanner_status is None:
            scanner = shutil.which("rg")
            self.assertIsNotNone(scanner, "workflow fixture tests require ripgrep")
            # Git Bash can rebuild PATH on Windows; use the discovered executable.
            env["SCAN_EXECUTABLE"] = Path(scanner).as_posix()
            stub = 'rg() { "$SCAN_EXECUTABLE" "$@"; }\n'
        with tempfile.TemporaryDirectory() as directory:
            for filename, content in (files or {}).items():
                (Path(directory) / filename).write_text(content, encoding="utf-8")
            return subprocess.run(
                [bash, "--noprofile", "--norc", "-c", stub + scan_script()],
                cwd=directory, env=env, capture_output=True, text=True, timeout=10,
            )

    def test_no_match_is_clean(self):
        result = self.run_scan(1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK:", result.stdout)

    def test_match_blocks_release(self):
        result = self.run_scan(0, "./sample.txt:1:synthetic violation")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("OK:", result.stdout)

    def test_scanner_errors_are_unknown_and_blocked(self):
        for status in (2, 127):
            for output in ("", "./sample.txt:1:partial result"):
                with self.subTest(status=status, partial_output=bool(output)):
                    result = self.run_scan(status, output)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("UNKNOWN", result.stdout + result.stderr)
                    self.assertNotIn("OK:", result.stdout)

    def test_policy_is_evaluated_on_source_content_only(self):
        # The forbidden-domain fixture exists only in the temporary test directory.
        domain = "a11oy" + ".com"
        for filename in ("sample.txt", "forbidden.txt", "never.txt"):
            with self.subTest(filename=filename):
                result = self.run_scan(files={filename: "visit " + domain})
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(filename + ":1:", result.stdout)
        for guard in ("never", "FORBIDDEN", "not in", "assertNotIn",
                      "does not appear", "is not a surface", "blocklist"):
            with self.subTest(guard=guard):
                result = self.run_scan(files={
                    "sample.txt": guard + " " + domain + "\n" + domain + " " + guard,
                })
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.run_scan(files={"sample.txt": "https://a-11-oy.com\nhttps://a11oy.net"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
