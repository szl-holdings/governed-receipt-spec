"""Keep this repository's CodeQL steps pinned to one compatible action revision.

This is a focused source-format regression, not a general YAML parser or a
replacement for native CodeQL analysis. The existing verify workflow discovers
these tests; no network, new dependency, publisher or provider call is used.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(.*?)\s*(?:#.*)?$")
PREFIX = "github/codeql-action/"


def require_lockstep(text: str) -> str:
    """Read literal uses entries in the maintained workflow's block format."""
    components = {}
    for line in text.splitlines():
        match = USES.fullmatch(line)
        if match is None:
            continue
        reference = match.group(1)
        if reference.startswith(("'", '"')) and reference[-1:] == reference[:1]:
            reference = reference[1:-1]
        if not reference.startswith(PREFIX):
            continue
        component, separator, revision = reference[len(PREFIX):].partition("@")
        if not separator or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
            raise ValueError("CodeQL component requires an immutable full commit")
        if component in components:
            raise ValueError("duplicate CodeQL component")
        components[component] = revision
    if not {"init", "analyze"}.issubset(components):
        raise ValueError("CodeQL init and analyze must both be present")
    revisions = set(components.values())
    if len(revisions) != 1:
        raise ValueError("CodeQL components must use one revision")
    return revisions.pop()


class CodeQLLockstepTests(unittest.TestCase):
    def workflow(self, init="a" * 40, analyze="a" * 40):
        return (f"      - uses: {PREFIX}init@{init}\n"
                f"      - uses: {PREFIX}analyze@{analyze}\n")

    def test_committed_workflow_uses_one_immutable_revision(self):
        require_lockstep((ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8"))

    def test_mixed_revisions_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "one revision"):
            require_lockstep(self.workflow(analyze="b" * 40))

    def test_short_mutable_and_malformed_refs_are_rejected(self):
        for ref in ("v4", "v4.38.0", "abc1234", "", "g" * 40, "a" * 41):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                require_lockstep(self.workflow(init=ref))

    def test_missing_components_cannot_pass_vacuously(self):
        for text in ("", f"uses: {PREFIX}init@{'a' * 40}",
                     f"uses: {PREFIX}analyze@{'a' * 40}"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                require_lockstep(text)

    def test_duplicate_components_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            require_lockstep(self.workflow() + f"uses: {PREFIX}init@{'a' * 40}\n")

    def test_additional_codeql_component_cannot_drift(self):
        with self.assertRaisesRegex(ValueError, "one revision"):
            require_lockstep(self.workflow() + f"uses: {PREFIX}autobuild@{'b' * 40}\n")

    def test_comments_and_unrelated_actions_do_not_select_the_pin(self):
        text = (f"# uses: {PREFIX}init@{'b' * 40}\nuses: actions/checkout@v7\n"
                + self.workflow().replace("\n", " # retained version comment\n"))
        self.assertEqual(require_lockstep(text), "a" * 40)

    def test_quoted_literal_uses_are_supported(self):
        for quote in ("'", '"'):
            text = "\n".join(f"uses: {quote}{PREFIX}{step}@{'b' * 40}{quote} # comment"
                             for step in ("init", "analyze"))
            self.assertEqual(require_lockstep(text), "b" * 40)

    def test_future_paired_revision_is_not_hard_coded(self):
        self.assertEqual(require_lockstep(self.workflow("c" * 40, "c" * 40)), "c" * 40)


if __name__ == "__main__":
    unittest.main()
