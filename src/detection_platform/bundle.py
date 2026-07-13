"""Locate and validate the self-contained rule and dataset bundle."""

from __future__ import annotations

from pathlib import Path

from .errors import ValidationError


def default_bundle_root() -> Path:
    return Path(__file__).with_name("bundle")


def resolve_inside(bundle_root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValidationError(
            f"bundle path must be relative and traversal-free: {relative}"
        )
    root = bundle_root.resolve()
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root):
        raise ValidationError(f"bundle path escapes root: {relative}")
    return resolved
