from __future__ import annotations

import unittest
from unittest.mock import patch

from detection_platform.corpus import load_corpus, verify_provenance
from detection_platform.errors import IntegrityError, ValidationError

from .helpers import BUNDLE, BundleCopy


class CorpusTests(unittest.TestCase):
    def test_corpus_is_integrity_checked_and_self_contained(self) -> None:
        cases, datasets = load_corpus(BUNDLE)
        self.assertEqual(24, len(cases))
        self.assertEqual(4, len(datasets))
        self.assertEqual(len(cases), len({item.id for item in cases}))
        self.assertEqual(22, sum(item.replay for item in cases))
        self.assertEqual({"event", "artifact"}, {item.kind for item in cases})

    def test_vendored_autonomous_provenance_is_valid(self) -> None:
        result = verify_provenance(BUNDLE)
        self.assertTrue(result["valid"])
        self.assertEqual("autonomous-incident-simulator", result["source_project"])
        self.assertEqual("payroll-no-malware", result["source_scenario"])
        self.assertEqual(64, len(result["canonical_report_sha256"]))

    def test_mutated_telemetry_is_rejected(self) -> None:
        copied = BundleCopy()
        try:
            telemetry = (
                copied.path / "datasets" / "autonomous-payroll" / "telemetry.jsonl"
            )
            telemetry.write_text(
                telemetry.read_text(encoding="utf-8") + "\n", encoding="utf-8"
            )
            with self.assertRaises(IntegrityError):
                load_corpus(copied.path)
        finally:
            copied.cleanup()

    def test_upstream_byte_comparison_when_explicitly_supplied(self) -> None:
        upstream = BUNDLE / "datasets" / "autonomous-payroll"
        result = verify_provenance(BUNDLE, upstream)
        self.assertTrue(all(result["checks"].values()))

    def test_telemetry_size_limit_is_enforced_before_parsing(self) -> None:
        with patch("detection_platform.corpus.MAX_TELEMETRY_BYTES", 1):
            with self.assertRaisesRegex(ValidationError, "exceeds size limit"):
                load_corpus(BUNDLE)


if __name__ == "__main__":
    unittest.main()
