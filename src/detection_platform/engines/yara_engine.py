"""YARA execution through the official yara-python compiler/runtime."""

from __future__ import annotations

import re
from dataclasses import dataclass

import yara  # type: ignore[import-not-found]

from ..errors import UnsupportedSyntaxError, ValidationError
from ..models import CorpusCase, RuleManifest


_RULE_NAME = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\b")


@dataclass(frozen=True)
class YaraMatcher:
    manifest: RuleManifest
    compiled: object
    case_kind: str = "artifact"

    def match(self, case: CorpusCase) -> bool:
        if case.kind != self.case_kind or not isinstance(case.payload, bytes):
            return False
        try:
            matches = self.compiled.match(data=case.payload, timeout=1)  # type: ignore[attr-defined]
        except yara.TimeoutError as exc:
            raise ValidationError(f"YARA evaluation timed out for {case.id}") from exc
        return any(match.rule == self.manifest.entrypoint for match in matches)


def compile_yara(manifest: RuleManifest) -> YaraMatcher:
    source = manifest.source_path.read_text(encoding="utf-8")
    lowered = source.lower()
    if re.search(r"^\s*(include|import)\b", lowered, flags=re.MULTILINE):
        raise UnsupportedSyntaxError(
            "YARA includes and modules are outside the supported profile"
        )
    declared = set(_RULE_NAME.findall(source))
    if manifest.entrypoint not in declared:
        raise ValidationError("YARA entrypoint is not declared in the source")
    try:
        compiled = yara.compile(filepath=str(manifest.source_path))
    except yara.SyntaxError as exc:
        raise ValidationError(
            f"invalid YARA syntax in {manifest.source}: {exc}"
        ) from exc
    return YaraMatcher(manifest=manifest, compiled=compiled)
