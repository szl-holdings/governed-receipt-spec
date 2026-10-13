"""The informational browser front must not become a receipt-verdict path."""
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

class Elements(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.nodes = []
        self.feed(source)
    def handle_starttag(self, tag, attrs):
        self.nodes.append((tag, dict(attrs)))

class BrowserStatusBoundary(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "space/governed-receipt-verifier/index.html").read_text(encoding="utf-8")
        self.nodes = Elements(self.source).nodes
    def test_no_receipt_input_script_frame_or_automatic_navigation(self):
        forbidden = {"script", "form", "input", "textarea", "button", "iframe", "object", "embed"}
        self.assertFalse(forbidden.intersection(tag for tag, _ in self.nodes))
        for tag, attrs in self.nodes:
            self.assertFalse(any(key.lower().startswith("on") for key in attrs))
            self.assertNotEqual(attrs.get("http-equiv", "").casefold(), "refresh")
            self.assertNotIn("contenteditable", attrs)
            if tag == "a":
                self.assertTrue(attrs["href"].startswith(("https://", "#")))
    def test_blocked_status_and_original_warning_remain_visible(self):
        text = " ".join(re.sub(r"<[^>]+>", " ", self.source).split())
        for statement in (
            "BLOCKED · NO VERIFICATION PERFORMED",
            "could report PASS without checking claimed hashes or cryptographic signatures",
            "Do not use its earlier verdicts as evidence of integrity, signer identity, or authorization.",
            "without one, signature authentication is skipped.",
            "A valid signature alone does not establish signer trust or authorize a governed action.",
        ):
            self.assertIn(statement, text)
    def test_offline_path_is_owned_and_no_remote_assets_are_loaded(self):
        hrefs = [a["href"] for tag, a in self.nodes if tag == "a"]
        self.assertIn("https://github.com/szl-holdings/governed-receipt-spec#verify-in-one-command", hrefs)
        self.assertFalse(any(tag in {"link", "img"} for tag, _ in self.nodes))
    def test_native_mark_retains_canonical_source_bytes(self):
        marks = re.findall(r"<svg\b.*?</svg>", self.source, flags=re.S)
        self.assertEqual(len(marks), 1)
        self.assertEqual(sha256((marks[0]+"\n").encode()).hexdigest(), "6e2b7d72a3af3d9602b79de41df0194ede6496a9661f057108ec224c0efc92e6")
    def test_skip_target_is_focusable_main_and_one_heading(self):
        self.assertIn(("main", {"id": "main", "class": "wrap", "tabindex": "-1"}), self.nodes)
        skip = [a for tag, a in self.nodes if tag == "a" and a.get("class") == "skip-link"]
        self.assertEqual(skip[0]["href"], "#main")
        self.assertEqual(sum(tag == "h1" for tag, _ in self.nodes), 1)

if __name__ == "__main__":
    unittest.main()
