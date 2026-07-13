from __future__ import annotations

import copy
import unittest
from datetime import date

from detection_platform.audit import verify_audit_chain
from detection_platform.errors import IntegrityError
from detection_platform.replay import functional_view, run_replay

from .helpers import BUNDLE


class ReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = run_replay(BUNDLE, date(2026, 7, 13))

    def test_summary_and_expected_policy_outcomes(self) -> None:
        summary = self.report["summary"]
        self.assertEqual(7, summary["rule_count"])
        self.assertEqual(22, summary["replay_case_count"])
        self.assertEqual(14, summary["unit_test_count"])
        self.assertEqual(4, summary["promote_count"])
        self.assertEqual(2, summary["hold_count"])
        self.assertEqual(1, summary["reject_count"])
        self.assertTrue(summary["all_expected_decisions_met"])

    def test_noise_silence_and_redundancy_are_measured(self) -> None:
        diagnostics = self.report["diagnostics"]
        self.assertEqual(["sigma.log-deletion-canary"], diagnostics["silent_rules"])
        self.assertEqual(
            ["sigma.broad-authentication-candidate"], diagnostics["noisy_rules"]
        )
        self.assertEqual(1, len(diagnostics["redundant_pairs"]))
        self.assertEqual(
            "sigma.payroll-sensitive-read-shadow",
            diagnostics["redundant_pairs"][0]["redundant_rule_id"],
        )

    def test_good_rules_have_perfect_functional_metrics(self) -> None:
        by_id = {item["rule"]["id"]: item for item in self.report["rules"]}
        for rule_id in (
            "sigma.payroll-sensitive-read",
            "sigma.identity-session-anomaly",
            "falco.payroll-remote-login",
            "yara.simulated-payroll-export",
        ):
            with self.subTest(rule=rule_id):
                item = by_id[rule_id]
                self.assertEqual(1.0, item["metrics"]["precision"])
                self.assertEqual(1.0, item["metrics"]["recall"])
                self.assertEqual(0.0, item["metrics"]["false_positive_rate"])
                self.assertEqual("PROMOTE", item["lifecycle"]["decision"])

    def test_functional_output_is_deterministic_while_latency_is_measured(self) -> None:
        second = run_replay(BUNDLE, date(2026, 7, 13))
        self.assertEqual(functional_view(self.report), functional_view(second))
        self.assertEqual(self.report["functional_sha256"], second["functional_sha256"])
        self.assertGreater(self.report["measurement"]["wall_clock_latency_ms"], 0)

    def test_audit_chain_detects_tampering(self) -> None:
        self.assertTrue(verify_audit_chain(self.report["audit"]))
        changed = copy.deepcopy(self.report["audit"])
        changed[1]["decision"] = (
            "PROMOTE" if changed[1].get("decision") != "PROMOTE" else "REJECT"
        )
        with self.assertRaises(IntegrityError):
            verify_audit_chain(changed)

    def test_expiration_is_evaluated_at_explicit_date(self) -> None:
        expired = run_replay(BUNDLE, date(2028, 1, 1))
        self.assertEqual(7, len(expired["diagnostics"]["expired_rules"]))
        self.assertTrue(
            all(item["lifecycle"]["decision"] == "REJECT" for item in expired["rules"])
        )


if __name__ == "__main__":
    unittest.main()
