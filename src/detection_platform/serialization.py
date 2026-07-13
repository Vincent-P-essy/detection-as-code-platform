"""Canonical JSON and digest helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import to_jsonable


def canonical_json(value: Any) -> str:
    return json.dumps(
        to_jsonable(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def pretty_json(value: Any) -> str:
    return (
        json.dumps(to_jsonable(value), ensure_ascii=False, sort_keys=True, indent=2)
        + "\n"
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
