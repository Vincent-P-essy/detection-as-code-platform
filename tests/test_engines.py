from __future__ import annotations

import unittest

import yara  # type: ignore[import-untyped]

from detection_platform.corpus import load_corpus
from detection_platform.engines import compile_rule
from detection_platform.manifest import load_manifests

from .helpers import BUNDLE


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cases, _ = load_corpus(BUNDLE)
        cls.cases = {item.id: item for item in cases}
        cls.manifests = {item.id: item for item in load_manifests(BUNDLE)}

    def _assert_declared_tests(self, rule_id: str) -> None:
        manifest = self.manifests[rule_id]
        matcher = compile_rule(manifest)
        for case_id in manifest.tests.positive_cases:
            self.assertTrue(matcher.match(self.cases[case_id]), case_id)
        for case_id in manifest.tests.negative_cases:
            self.assertFalse(matcher.match(self.cases[case_id]), case_id)

    def test_sigma_positive_and_negative(self) -> None:
        self._assert_declared_tests("sigma.payroll-sensitive-read")
        self._assert_declared_tests("sigma.identity-session-anomaly")

    def test_falco_positive_and_negative(self) -> None:
        self._assert_declared_tests("falco.payroll-remote-login")

    def test_official_yara_runtime_positive_and_negative(self) -> None:
        self.assertEqual("4.5.4", yara.__version__)
        self._assert_declared_tests("yara.simulated-payroll-export")

    def test_deliberately_broad_candidate_fails_its_negative_test(self) -> None:
        manifest = self.manifests["sigma.broad-authentication-candidate"]
        matcher = compile_rule(manifest)
        negative = self.cases[manifest.tests.negative_cases[0]]
        self.assertTrue(matcher.match(negative))


if __name__ == "__main__":
    unittest.main()
