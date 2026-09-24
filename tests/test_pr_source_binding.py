#!/usr/bin/env python3
"""Regression contract for exact-source pull-request qualification."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ".github/workflows/verify.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/base-python-ci.yml",
    ".github/workflows/forbidden-domain.yml",
)
SOURCE_EXPRESSION = "SOURCE_REVISION: ${{ github.event.pull_request.head.sha || github.sha }}"
CHECKOUT_REF = "ref: ${{ env.SOURCE_REVISION }}"


class ExactPullRequestSourceContractTests(unittest.TestCase):
    def test_pr_workflows_bind_and_prove_exact_event_source(self):
        for relative_path in WORKFLOWS:
            with self.subTest(workflow=relative_path):
                text = (ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn(SOURCE_EXPRESSION, text)
                self.assertIn(CHECKOUT_REF, text)
                self.assertIn('actual="$(git rev-parse HEAD)"', text)
                self.assertIn('test "$actual" = "$SOURCE_REVISION"', text)
                self.assertIn("persist-credentials: false", text)


if __name__ == "__main__":
    unittest.main()
