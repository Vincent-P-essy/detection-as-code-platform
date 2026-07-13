"""Strict JSON loading with duplicate-key rejection and size limits."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Tuple

from .errors import ValidationError


def _unique_object(pairs: List[Tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def loads_json(text: str, source: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_unique_object)
    except ValidationError:
        raise
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"invalid JSON in {source}: line {exc.lineno}, column {exc.colno}"
        ) from exc


def load_json(path: Path, maximum_bytes: int = 16_777_216) -> Any:
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise ValidationError(f"file does not exist: {path}") from exc
    if size > maximum_bytes:
        raise ValidationError(f"JSON file exceeds {maximum_bytes} bytes: {path}")
    return loads_json(path.read_text(encoding="utf-8"), str(path))
