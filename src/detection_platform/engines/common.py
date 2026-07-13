"""Shared field resolution and closed boolean-expression parser."""

from __future__ import annotations

import re
from typing import Any, List, Mapping, Sequence, Tuple

from ..errors import UnsupportedSyntaxError


def resolve_field(value: Mapping[str, Any], dotted: str) -> Any:
    current: Any = value
    for segment in dotted.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return None
        current = current[segment]
    return current


_BOOLEAN_TOKEN = re.compile(r"\s*(?:(and|or|not)\b|([A-Za-z_][A-Za-z0-9_]*)|(\()|(\)))")


class NamedBooleanExpression:
    """Parse `name and not other` expressions without dynamic evaluation."""

    def __init__(self, text: str, allowed_names: Sequence[str]) -> None:
        self.tokens = self._tokenize(text)
        self.position = 0
        self.allowed_names = set(allowed_names)
        self.tree = self._parse_or()
        if self.position != len(self.tokens):
            raise UnsupportedSyntaxError(
                f"unexpected condition token: {self.tokens[self.position]}"
            )

    @staticmethod
    def _tokenize(text: str) -> Tuple[str, ...]:
        if len(text) > 500:
            raise UnsupportedSyntaxError("condition exceeds 500 characters")
        tokens: List[str] = []
        position = 0
        while position < len(text):
            match = _BOOLEAN_TOKEN.match(text, position)
            if not match:
                raise UnsupportedSyntaxError(
                    f"unsupported condition syntax near character {position}"
                )
            token = next(item for item in match.groups() if item is not None)
            tokens.append(token)
            position = match.end()
        if not tokens:
            raise UnsupportedSyntaxError("condition is empty")
        return tuple(tokens)

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self, token: str | None = None) -> str:
        current = self._peek()
        if current is None or (token is not None and current != token):
            raise UnsupportedSyntaxError(f"expected {token or 'condition token'}")
        self.position += 1
        return current

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
        return self._parse_atom()

    def _parse_atom(self) -> Any:
        if self._peek() == "(":
            self._take("(")
            node = self._parse_or()
            self._take(")")
            return node
        name = self._take()
        if name in {"and", "or", "not", "(", ")"} or name not in self.allowed_names:
            raise UnsupportedSyntaxError(f"unknown selection in condition: {name}")
        return ("name", name)

    def evaluate(self, values: Mapping[str, bool]) -> bool:
        def walk(node: Any) -> bool:
            kind = node[0]
            if kind == "name":
                return bool(values[node[1]])
            if kind == "not":
                return not walk(node[1])
            if kind == "and":
                return walk(node[1]) and walk(node[2])
            if kind == "or":
                return walk(node[1]) or walk(node[2])
            raise AssertionError(f"unknown boolean node: {kind}")

        return walk(self.tree)
