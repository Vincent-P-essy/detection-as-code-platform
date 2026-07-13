#!/usr/bin/env python3
"""Verify committed measurements and reproduce their functional decision digest."""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from detection_platform.audit import verify_audit_chain  # noqa: E402
from detection_platform.bundle import default_bundle_root  # noqa: E402
from detection_platform.errors import ValidationError  # noqa: E402
from detection_platform.jsonutil import load_json  # noqa: E402
from detection_platform.replay import functional_view, run_replay  # noqa: E402
from detection_platform.serialization import digest, file_sha256  # noqa: E402


SNAPSHOT = ROOT / "snapshots" / "2026-07-13"
EXPECTED_FILES = {
    "audit-chain.json",
    "replay-report.json",
    "replay-report.md",
    "rule-metrics.csv",
}


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{label} must be an object")
    return value


def main() -> int:
    manifest = _mapping(load_json(SNAPSHOT / "snapshot-manifest.json"), "snapshot")
    expected_keys = {
        "snapshot_version",
        "as_of",
        "functional_sha256",
        "files",
        "latency_note",
    }
    if set(manifest) != expected_keys or manifest["snapshot_version"] != "1.0":
        raise ValidationError("unsupported snapshot manifest contract")
    files = _mapping(manifest["files"], "snapshot.files")
    if set(files) != EXPECTED_FILES:
        raise ValidationError("snapshot manifest has an unexpected file set")
    file_checks = {
        name: file_sha256(SNAPSHOT / name) == expected
        for name, expected in files.items()
    }

    committed_report = _mapping(
        load_json(SNAPSHOT / "replay-report.json"), "committed report"
    )
    committed_functional = digest(functional_view(committed_report))
    as_of = date.fromisoformat(str(manifest["as_of"]))
    reproduced = run_replay(default_bundle_root(), as_of)
    checks = {
        "snapshot_files_unchanged": all(file_checks.values()),
        "committed_functional_digest_valid": committed_functional
        == committed_report.get("functional_sha256"),
        "manifest_matches_committed_report": manifest["functional_sha256"]
        == committed_report.get("functional_sha256"),
        "functional_digest_reproduced": reproduced["functional_sha256"]
        == manifest["functional_sha256"],
        "committed_audit_valid": verify_audit_chain(committed_report["audit"]),
        "reproduced_audit_valid": verify_audit_chain(reproduced["audit"]),
    }
    passed = all(file_checks.values()) and all(checks.values())
    print(
        json.dumps(
            {
                "passed": passed,
                "checks": checks,
                "file_checks": file_checks,
                "functional_sha256": reproduced["functional_sha256"],
                "latency_recompared": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
