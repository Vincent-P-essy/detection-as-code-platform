#!/usr/bin/env python3
"""Functional determinism, policy outcome, and dataset integration gate."""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from detection_platform.audit import verify_audit_chain  # noqa: E402
from detection_platform.bundle import default_bundle_root  # noqa: E402
from detection_platform.corpus import verify_provenance  # noqa: E402
from detection_platform.replay import functional_view, run_replay  # noqa: E402


def main() -> int:
    bundle = default_bundle_root()
    first = run_replay(bundle, date(2026, 7, 13))
    second = run_replay(bundle, date(2026, 7, 13))
    checks = {
        "functional_determinism": functional_view(first) == functional_view(second),
        "functional_digest_stable": first["functional_sha256"]
        == second["functional_sha256"],
        "expected_decisions": first["summary"]["all_expected_decisions_met"],
        "all_engines_exercised": first["coverage"]["engines"]
        == ["falco", "sigma", "yara"],
        "noise_measured": bool(first["diagnostics"]["noisy_rules"]),
        "silence_measured": bool(first["diagnostics"]["silent_rules"]),
        "redundancy_measured": bool(first["diagnostics"]["redundant_pairs"]),
        "audit_chain_valid": verify_audit_chain(first["audit"]),
        "vendored_provenance_valid": verify_provenance(bundle)["valid"],
        "no_deployment_effect": all(
            item["lifecycle"]["deployment_effect"] == "simulation-only"
            for item in first["rules"]
        ),
    }
    passed = all(checks.values())
    print(
        json.dumps(
            {
                "passed": passed,
                "checks": checks,
                "functional_sha256": first["functional_sha256"],
                "summary": first["summary"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
