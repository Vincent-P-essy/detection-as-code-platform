from __future__ import annotations

import unittest
from pathlib import Path

from detection_platform.engines import compile_rule
from detection_platform.errors import (
    IntegrityError,
    UnsupportedSyntaxError,
    ValidationError,
)
from detection_platform.manifest import load_manifest, load_manifests
from detection_platform.serialization import file_sha256

from .helpers import BUNDLE, BundleCopy


def repin_source(manifest_path: Path, source_path: Path) -> None:
    text = manifest_path.read_text(encoding="utf-8")
    lines = [
        (
            f"{line[: len(line) - len(line.lstrip())]}source_sha256: {file_sha256(source_path)}"
            if line.lstrip().startswith("source_sha256:")
            else line
        )
        for line in text.splitlines()
    ]
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class ManifestTests(unittest.TestCase):
    def test_all_manifests_are_complete_and_compile(self) -> None:
        manifests = load_manifests(BUNDLE)
        self.assertEqual(7, len(manifests))
        self.assertEqual(
            {"sigma", "yara", "falco"}, {item.engine.value for item in manifests}
        )
        for item in manifests:
            with self.subTest(rule=item.id):
                self.assertTrue(item.owner)
                self.assertTrue(item.threat.techniques)
                self.assertTrue(item.tests.positive_cases)
                self.assertTrue(item.tests.negative_cases)
                self.assertGreater(item.expires_at, item.modified_at)
                self.assertTrue(item.source_sha256)
                self.assertEqual(item.revision, item.change_history[-1].revision)
                self.assertEqual(
                    item.source_sha256, item.change_history[-1].source_sha256
                )
                compile_rule(item)

    def test_duplicate_yaml_key_is_rejected(self) -> None:
        copied = BundleCopy()
        try:
            manifest = copied.path / "manifests" / "sigma-payroll-sensitive-read.yml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8") + "kind: Duplicate\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValidationError, "duplicate YAML key"):
                load_manifest(manifest, copied.path)
        finally:
            copied.cleanup()

    def test_manifest_unknown_field_is_rejected(self) -> None:
        copied = BundleCopy()
        try:
            manifest = copied.path / "manifests" / "sigma-payroll-sensitive-read.yml"
            text = manifest.read_text(encoding="utf-8").replace(
                "  status: stable\n", "  status: stable\n  unsupported: true\n"
            )
            manifest.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "unsupported fields"):
                load_manifest(manifest, copied.path)
        finally:
            copied.cleanup()

    def test_path_traversal_is_rejected(self) -> None:
        copied = BundleCopy()
        try:
            manifest = copied.path / "manifests" / "sigma-payroll-sensitive-read.yml"
            text = manifest.read_text(encoding="utf-8").replace(
                "rules/sigma/payroll-sensitive-read.yml", "../outside.yml"
            )
            manifest.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "traversal-free"):
                load_manifest(manifest, copied.path)
        finally:
            copied.cleanup()

    def test_sigma_unsupported_quantifier_fails_closed(self) -> None:
        copied = BundleCopy()
        try:
            source = copied.path / "rules" / "sigma" / "payroll-sensitive-read.yml"
            source.write_text(
                source.read_text(encoding="utf-8").replace(
                    "condition: selection", "condition: 1 of selection"
                ),
                encoding="utf-8",
            )
            manifest_path = (
                copied.path / "manifests" / "sigma-payroll-sensitive-read.yml"
            )
            repin_source(manifest_path, source)
            manifest = load_manifest(manifest_path, copied.path)
            with self.assertRaises(UnsupportedSyntaxError):
                compile_rule(manifest)
        finally:
            copied.cleanup()

    def test_falco_unknown_field_fails_closed(self) -> None:
        copied = BundleCopy()
        try:
            source = copied.path / "rules" / "falco" / "payroll-remote-login.yml"
            source.write_text(
                source.read_text(encoding="utf-8").replace(
                    "evt.type", "proc.unbounded"
                ),
                encoding="utf-8",
            )
            manifest_path = copied.path / "manifests" / "falco-payroll-remote-login.yml"
            repin_source(manifest_path, source)
            manifest = load_manifest(manifest_path, copied.path)
            with self.assertRaisesRegex(
                UnsupportedSyntaxError, "unsupported Falco field"
            ):
                compile_rule(manifest)
        finally:
            copied.cleanup()

    def test_sigma_wildcards_fail_closed(self) -> None:
        copied = BundleCopy()
        try:
            source = copied.path / "rules" / "sigma" / "payroll-sensitive-read.yml"
            source.write_text(
                source.read_text(encoding="utf-8").replace(
                    "sensitive_records_read", "sensitive_*"
                ),
                encoding="utf-8",
            )
            manifest_path = (
                copied.path / "manifests" / "sigma-payroll-sensitive-read.yml"
            )
            repin_source(manifest_path, source)
            manifest = load_manifest(manifest_path, copied.path)
            with self.assertRaisesRegex(UnsupportedSyntaxError, "wildcard semantics"):
                compile_rule(manifest)
        finally:
            copied.cleanup()

    def test_yara_include_is_rejected_before_compilation(self) -> None:
        copied = BundleCopy()
        try:
            source = copied.path / "rules" / "yara" / "simulated-payroll-export.yar"
            source.write_text(
                'include "external.yar"\n' + source.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            manifest_path = (
                copied.path / "manifests" / "yara-simulated-payroll-export.yml"
            )
            repin_source(manifest_path, source)
            manifest = load_manifest(manifest_path, copied.path)
            with self.assertRaisesRegex(UnsupportedSyntaxError, "includes and modules"):
                compile_rule(manifest)
        finally:
            copied.cleanup()

    def test_mutated_rule_source_is_rejected_before_compilation(self) -> None:
        copied = BundleCopy()
        try:
            source = copied.path / "rules" / "sigma" / "payroll-sensitive-read.yml"
            source.write_text(
                source.read_text(encoding="utf-8") + "\n# unauthorized mutation\n",
                encoding="utf-8",
            )
            manifest = copied.path / "manifests" / "sigma-payroll-sensitive-read.yml"
            with self.assertRaisesRegex(IntegrityError, "source hash mismatch"):
                load_manifest(manifest, copied.path)
        finally:
            copied.cleanup()

    def test_change_history_must_contain_each_revision(self) -> None:
        copied = BundleCopy()
        try:
            manifest = copied.path / "manifests" / "sigma-payroll-sensitive-read.yml"
            text = manifest.read_text(encoding="utf-8").replace(
                "  - revision: 1\n", "  - revision: 2\n"
            )
            manifest.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "each revision in order"):
                load_manifest(manifest, copied.path)
        finally:
            copied.cleanup()


if __name__ == "__main__":
    unittest.main()
