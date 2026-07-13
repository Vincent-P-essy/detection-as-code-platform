"""Executable, fail-closed subset of Sigma event-selection semantics.

Supported conditions: named selections joined by `and`, `or`, `not`, and
parentheses. Supported field modifiers: exact matching (default), `contains`,
`startswith`, and `endswith`. Aggregations, wildcards, correlations, quantifiers,
and backend-specific pipelines are rejected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from ..errors import UnsupportedSyntaxError, ValidationError
from ..models import CorpusCase, RuleManifest
from ..yamlutil import load_yaml
from .common import NamedBooleanExpression, resolve_field


_TOP_LEVEL = {
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "modified",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
}
_MODIFIERS = {"contains", "startswith", "endswith"}
_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


@dataclass(frozen=True)
class SigmaSelection:
    clauses: Tuple[Tuple[str, str | None, Tuple[Any, ...]], ...]

    def matches(self, event: Mapping[str, Any]) -> bool:
        for field, modifier, expected_values in self.clauses:
            actual = resolve_field(event, field)
            if modifier is None:
                matched = any(actual == expected for expected in expected_values)
            elif not isinstance(actual, str):
                matched = False
            elif modifier == "contains":
                matched = any(str(expected) in actual for expected in expected_values)
            elif modifier == "startswith":
                matched = any(
                    actual.startswith(str(expected)) for expected in expected_values
                )
            else:
                matched = any(
                    actual.endswith(str(expected)) for expected in expected_values
                )
            if not matched:
                return False
        return True


@dataclass(frozen=True)
class SigmaMatcher:
    manifest: RuleManifest
    selections: Mapping[str, SigmaSelection]
    condition: NamedBooleanExpression
    case_kind: str = "event"

    def match(self, case: CorpusCase) -> bool:
        if case.kind != self.case_kind or not isinstance(case.payload, Mapping):
            return False
        values = {
            name: selection.matches(case.payload)
            for name, selection in self.selections.items()
        }
        return self.condition.evaluate(values)


def _selection(name: str, raw: Any) -> SigmaSelection:
    if not isinstance(raw, Mapping) or not raw:
        raise UnsupportedSyntaxError(
            f"Sigma selection {name} must be a non-empty mapping"
        )
    clauses = []
    for raw_field, raw_expected in raw.items():
        if not isinstance(raw_field, str) or not raw_field:
            raise UnsupportedSyntaxError(
                f"Sigma selection {name} contains an invalid field"
            )
        parts = raw_field.split("|")
        if len(parts) > 2:
            raise UnsupportedSyntaxError(
                f"Sigma field has multiple unsupported modifiers: {raw_field}"
            )
        field = parts[0]
        if not _FIELD.fullmatch(field):
            raise UnsupportedSyntaxError(f"unsupported Sigma field name: {field}")
        modifier = parts[1] if len(parts) == 2 else None
        if modifier is not None and modifier not in _MODIFIERS:
            raise UnsupportedSyntaxError(f"unsupported Sigma modifier: {modifier}")
        if isinstance(raw_expected, list):
            expected = tuple(raw_expected)
        else:
            expected = (raw_expected,)
        if not expected or any(
            not isinstance(item, (str, int, float, bool)) for item in expected
        ):
            raise UnsupportedSyntaxError(
                f"Sigma field {raw_field} requires scalar values"
            )
        if any(
            isinstance(item, str) and ("*" in item or "?" in item) for item in expected
        ):
            raise UnsupportedSyntaxError(
                f"Sigma wildcard semantics are outside the supported profile: {raw_field}"
            )
        clauses.append((field, modifier, expected))
    return SigmaSelection(tuple(clauses))


def compile_sigma(manifest: RuleManifest) -> SigmaMatcher:
    raw = load_yaml(manifest.source_path)
    if not isinstance(raw, Mapping):
        raise ValidationError("Sigma document must be an object")
    unknown = set(raw) - _TOP_LEVEL
    required = {"title", "id", "logsource", "detection"}
    if unknown:
        raise UnsupportedSyntaxError(
            "unsupported Sigma top-level fields: " + ", ".join(sorted(unknown))
        )
    if required - set(raw):
        raise ValidationError(
            "Sigma document is missing required fields: "
            + ", ".join(sorted(required - set(raw)))
        )
    if not isinstance(raw["title"], str) or not raw["title"].strip():
        raise ValidationError("Sigma title must be a non-empty string")
    if raw["id"] != manifest.id:
        raise ValidationError("Sigma id must match manifest id")
    logsource = raw["logsource"]
    if not isinstance(logsource, Mapping) or not logsource:
        raise ValidationError("Sigma logsource must be a non-empty object")
    unsupported_logsource = set(logsource) - {
        "category",
        "product",
        "service",
        "definition",
    }
    if unsupported_logsource:
        raise UnsupportedSyntaxError(
            "unsupported Sigma logsource fields: "
            + ", ".join(sorted(unsupported_logsource))
        )
    if any(
        not isinstance(value, str) or not value.strip() for value in logsource.values()
    ):
        raise ValidationError("Sigma logsource values must be non-empty strings")
    detection = raw["detection"]
    if not isinstance(detection, Mapping) or "condition" not in detection:
        raise ValidationError("Sigma detection must contain condition")
    condition_raw = detection["condition"]
    if not isinstance(condition_raw, str):
        raise UnsupportedSyntaxError("Sigma condition must be a string")
    selections: Dict[str, SigmaSelection] = {}
    for name, value in detection.items():
        if name == "condition":
            continue
        if not isinstance(name, str) or not name.isidentifier():
            raise UnsupportedSyntaxError(f"Sigma selection name is unsupported: {name}")
        selections[name] = _selection(name, value)
    if not selections:
        raise ValidationError("Sigma detection contains no selections")
    condition = NamedBooleanExpression(condition_raw, tuple(selections))
    return SigmaMatcher(manifest=manifest, selections=selections, condition=condition)
