from __future__ import annotations

import csv
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from detection_platform.exporters import markdown_report, rules_csv, write_report_bundle
from detection_platform.replay import run_replay

from .helpers import BUNDLE


class ExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = run_replay(BUNDLE, date(2026, 7, 13))

    def test_csv_contains_one_row_per_rule(self) -> None:
        rows = list(csv.DictReader(rules_csv(self.report).splitlines()))
        self.assertEqual(7, len(rows))
        self.assertEqual({"sigma", "yara", "falco"}, {row["engine"] for row in rows})

    def test_markdown_is_honest_about_simulated_promotion(self) -> None:
        rendered = markdown_report(self.report)
        self.assertIn("Promotion is simulated", rendered)
        self.assertIn("sigma.broad-authentication-candidate", rendered)

    def test_report_bundle_is_machine_and_human_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = write_report_bundle(self.report, Path(directory))
            self.assertEqual({"json", "csv", "markdown", "audit"}, set(paths))
            self.assertTrue(all(Path(path).is_file() for path in paths.values()))
            exported = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
            self.assertEqual(
                self.report["functional_sha256"], exported["functional_sha256"]
            )


if __name__ == "__main__":
    unittest.main()
