"""Executable subset of Falco filter expressions over normalized events."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any, List, Mapping, Tuple

from ..errors import UnsupportedSyntaxError, ValidationError
from ..models import CorpusCase, RuleManifest
from ..yamlutil import load_yaml
from .common import resolve_field


_FIELDS = {
    "evt.type": "event_type",
    "evt.source": "source",
    "evt.outcome": "outcome",
    "target.role": "target.role",
    "mitre.technique": "technique.id",
    "actor.name": "actor.display_name",
}
_TOKEN = re.compile(
    r"\s*(?:(?P<operator>!=|=)|(?P<lpar>\()|(?P<rpar>\))|(?P<comma>,)|"
    r"(?P<string>\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*')|"
    r"(?P<word>[A-Za-z_][A-Za-z0-9_.:-]*))"
)


def _tokenize(text: str) -> Tuple[str, ...]:
    if not text or len(text) > 1000:
        raise UnsupportedSyntaxError(
            "Falco condition must contain 1 to 1000 characters"
        )
    tokens: List[str] = []
    position = 0
    while position < len(text):
        match = _TOKEN.match(text, position)
        if not match:
            raise UnsupportedSyntaxError(
                f"unsupported Falco syntax near character {position}"
            )
        token = next(item for item in match.groups() if item is not None)
        tokens.append(token)
        position = match.end()
    return tuple(tokens)


class FalcoExpression:
    def __init__(self, text: str) -> None:
        self.tokens = _tokenize(text)
        self.position = 0
        self.tree = self._parse_or()
        if self.position != len(self.tokens):
            raise UnsupportedSyntaxError(
                f"unexpected Falco token: {self.tokens[self.position]}"
            )

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self, expected: str | None = None) -> str:
        token = self._peek()
        if token is None or (expected is not None and token != expected):
            raise UnsupportedSyntaxError(f"expected {expected or 'Falco token'}")
        self.position += 1
        return token

    def _parse_or(self) -> Any:
        node = self._parse_and()
        while self._peek() == "or":
            self._take("or")
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self) -> Any:
        node = self._parse_not()
        while self._peek() == "and":
            self._take("and")
            node = ("and", node, self._parse_not())
        return node

    def _parse_not(self) -> Any:
        if self._peek() == "not":
            self._take("not")
            return ("not", self._parse_not())
        if self._peek() == "(":
            self._take("(")
            node = self._parse_or()
            self._take(")")
            return node
        return self._parse_comparison()

    def _value(self) -> Any:
        token = self._take()
        if token.startswith(('"', "'")):
            try:
                return ast.literal_eval(token)
            except (ValueError, SyntaxError) as exc:
                raise UnsupportedSyntaxError("invalid quoted Falco value") from exc
        if token in {"and", "or", "not", "in", "contains", "=", "!=", "(", ")", ","}:
            raise UnsupportedSyntaxError(f"invalid Falco value: {token}")
        return token

    def _parse_comparison(self) -> Any:
        field = self._take()
        if field not in _FIELDS:
            raise UnsupportedSyntaxError(f"unsupported Falco field: {field}")
        operator = self._take()
        if operator in {"=", "!=", "contains"}:
            return ("compare", field, operator, self._value())
        if operator == "in":
            self._take("(")
            values = [self._value()]
            while self._peek() == ",":
                self._take(",")
                values.append(self._value())
            self._take(")")
            return ("in", field, tuple(values))
        raise UnsupportedSyntaxError(f"unsupported Falco operator: {operator}")

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        def walk(node: Any) -> bool:
            kind = node[0]
            if kind == "not":
                return not walk(node[1])
            if kind == "and":
                return walk(node[1]) and walk(node[2])
            if kind == "or":
                return walk(node[1]) or walk(node[2])
            actual = resolve_field(event, _FIELDS[node[1]])
            if kind == "in":
                return bool(actual in node[2])
            operator, expected = node[2], node[3]
            if operator == "=":
                return bool(actual == expected)
            if operator == "!=":
                return bool(actual != expected)
            return isinstance(actual, str) and str(expected) in actual

        return walk(self.tree)


@dataclass(frozen=True)
class FalcoMatcher:
    manifest: RuleManifest
    expression: FalcoExpression
    case_kind: str = "event"

    def match(self, case: CorpusCase) -> bool:
        return (
            case.kind == self.case_kind
            and isinstance(case.payload, Mapping)
            and self.expression.evaluate(case.payload)
        )


def compile_falco(manifest: RuleManifest) -> FalcoMatcher:
    raw = load_yaml(manifest.source_path)
    if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], Mapping):
        raise UnsupportedSyntaxError(
            "Falco subset requires exactly one rule per YAML file"
        )
    data = raw[0]
    allowed = {"rule", "desc", "condition", "output", "priority", "tags", "enabled"}
    required = {"rule", "desc", "condition", "output", "priority", "tags"}
    if set(data) - allowed:
        raise UnsupportedSyntaxError(
            "unsupported Falco rule fields: " + ", ".join(sorted(set(data) - allowed))
        )
    if required - set(data):
        raise ValidationError(
            "Falco rule is missing fields: " + ", ".join(sorted(required - set(data)))
        )
    if data["rule"] != manifest.id:
        raise ValidationError("Falco rule name must match manifest id")
    for field in ("desc", "output"):
        if not isinstance(data[field], str) or not data[field].strip():
            raise ValidationError(f"Falco {field} must be a non-empty string")
    priorities = {
        "emergency",
        "alert",
        "critical",
        "error",
        "warning",
        "notice",
        "informational",
        "debug",
    }
    if (
        not isinstance(data["priority"], str)
        or data["priority"].lower() not in priorities
    ):
        raise ValidationError("Falco priority is invalid")
    if data.get("enabled", True) is not True:
        raise ValidationError("disabled Falco rules cannot enter replay")
    if not isinstance(data["condition"], str):
        raise ValidationError("Falco condition must be a string")
    if (
        not isinstance(data["tags"], list)
        or not data["tags"]
        or any(not isinstance(tag, str) or not tag.strip() for tag in data["tags"])
    ):
        raise ValidationError("Falco tags must be a non-empty string list")
    return FalcoMatcher(
        manifest=manifest, expression=FalcoExpression(data["condition"])
    )
