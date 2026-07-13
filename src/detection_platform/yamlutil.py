"""Safe YAML loader that rejects duplicate mapping keys."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .errors import ValidationError


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)  # type: ignore[no-untyped-call]
        if key in mapping:
            raise ValidationError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(  # type: ignore[no-untyped-call]
            value_node, deep=deep
        )
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def load_yaml_text(text: str, source: str) -> Any:
    try:
        return yaml.load(text, Loader=UniqueKeyLoader)
    except ValidationError:
        raise
    except yaml.YAMLError as exc:
        raise ValidationError(f"invalid YAML in {source}: {exc}") from exc


def load_yaml(path: Path, maximum_bytes: int = 262_144) -> Any:
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise ValidationError(f"file does not exist: {path}") from exc
    if size > maximum_bytes:
        raise ValidationError(f"YAML file exceeds {maximum_bytes} bytes: {path}")
    return load_yaml_text(path.read_text(encoding="utf-8"), str(path))
