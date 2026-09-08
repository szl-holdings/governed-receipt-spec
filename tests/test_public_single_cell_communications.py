# SPDX-License-Identifier: Apache-2.0
"""Narrow communication regressions; neither science review nor result execution."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "examples/public-single-cell"
PUBLIC_FILES = ("POST.md", "FIRST_COMMENT.md", "SCIENTIST_GUIDE.md", "REPRODUCIBILITY_CHECKLIST.md")
BRAND_WORDS = re.compile(r"\b(?:Doctrine|Khipu|PURIQ|IMMUNE|Kitaev[- ]surface)\b|Λ", re.I)
PINNED_EXAMPLE = "https://github.com/szl-holdings/governed-receipt-spec/tree/320983d22e76fc9b26af0b2cd20799c5000543fc/examples/public-single-cell"


class ScientificCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = {name: (ROOT / name).read_text(encoding="utf-8") for name in PUBLIC_FILES}
        cls.observed = json.loads((ROOT / "observed-run.json").read_text(encoding="utf-8"))

    def test_reader_facing_copy_does_not_require_internal_vocabulary(self):
        for name, text in self.docs.items():
            with self.subTest(name=name):
                self.assertIsNone(BRAND_WORDS.search(text))

    def test_post_contains_one_immutable_worked_example_not_an_org_shelf(self):
        urls = re.findall(r"https?://[^\s)]+", self.docs["POST.md"])
        self.assertEqual(urls, [PINNED_EXAMPLE])
        for text in self.docs.values():
            self.assertIsNone(re.search(r"https://huggingface\.co/SZLHOLDINGS/?(?=[\s)#]|$)", text, re.I))

    def test_post_size_and_bounded_scope_are_retained(self):
        text = self.docs["POST.md"]
        self.assertLessEqual(len(text.split()), 230)
        for phrase in ("processed", "unfiltered", "unsigned", "not trusted authorship or biological validity", "not a new gene-scoring method"):
            self.assertIn(phrase, text)

    def test_post_numbers_and_accession_agree_with_retained_record(self):
        summary = self.observed["summary"]
        text = self.docs["POST.md"]
        self.assertIn(summary["accession"], text)
        self.assertIn(f"{summary['cell_columns']:,}", text)
        self.assertEqual(summary["source_donor_label_count"], 4)
        self.assertIn("four source donor labels", text)

    def test_post_does_not_invent_a_scoring_or_signature_result(self):
        verification = self.observed["verification"]
        self.assertEqual(verification["scoring_methods_benchmarked"], [])
        self.assertIs(verification["signature_verified"], False)
        self.assertIs(verification["biological_claim_validated"], False)
        for phrase in ("outperforms", "state-of-the-art", "tamper-proof", "clinically validated", "44 models"):
            self.assertNotIn(phrase, self.docs["POST.md"].lower())

    def test_attribution_and_disclosure_are_not_replaced_by_branding(self):
        for name in ("POST.md", "FIRST_COMMENT.md"):
            self.assertIn("Muraro", self.docs[name])
        self.assertIn("10.1016/j.cels.2016.09.002", self.docs["FIRST_COMMENT.md"])
        self.assertIn("does not imply affiliation", self.docs["FIRST_COMMENT.md"])

    def test_proposed_benchmark_is_not_presented_as_executed(self):
        guide = self.docs["SCIENTIST_GUIDE.md"]
        self.assertIn("proposed study design, not an executed benchmark", guide)
        self.assertIn("not an independent external replication", guide)
        self.assertIn("10.1038/s41467-021-25960-2", guide)
        self.assertIn("10.1093/bioinformatics/btag055", guide)

    def test_scoped_local_document_links_exist(self):
        for name, text in self.docs.items():
            for target in re.findall(r"\]\(([^)]+)\)", text):
                if "://" in target or target.startswith("#"):
                    continue
                with self.subTest(file=name, target=target):
                    self.assertNotIn("..", Path(target).parts)
                    self.assertTrue((ROOT / target).is_file())


if __name__ == "__main__":
    unittest.main()
