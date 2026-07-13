"""Rule compiler dispatch for supported detection engines."""

from __future__ import annotations

from typing import Protocol

from ..models import CorpusCase, EngineKind, RuleManifest
from .falco import compile_falco
from .sigma import compile_sigma
from .yara_engine import compile_yara


class RuleMatcher(Protocol):
    @property
    def case_kind(self) -> str: ...

    def match(self, case: CorpusCase) -> bool: ...


def compile_rule(manifest: RuleManifest) -> RuleMatcher:
    if manifest.engine is EngineKind.SIGMA:
        return compile_sigma(manifest)
    if manifest.engine is EngineKind.FALCO:
        return compile_falco(manifest)
    return compile_yara(manifest)
