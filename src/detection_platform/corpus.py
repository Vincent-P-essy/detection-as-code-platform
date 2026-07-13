"""Integrity-checked loading of telemetry and artifact evaluation cases."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Set, Tuple

from .bundle import resolve_inside
from .errors import IntegrityError, ValidationError
from .jsonutil import load_json, loads_json
from .models import CorpusCase, DatasetMetadata
from .serialization import file_sha256


MAX_TELEMETRY_BYTES = 16_777_216
MAX_EVENT_BYTES = 1_048_576
MAX_ARTIFACT_BYTES = 8_388_608


def _object(
    value: Any, path: str, required: Set[str], optional: Set[str] = set()
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ValidationError(f"{path} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(
            f"{path} has unsupported fields: {', '.join(sorted(unknown))}"
        )
    return value


def _string(value: Any, path: str, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{path} must be boolean")
    return value


def _timestamp(event: Mapping[str, Any], source: str) -> datetime | None:
    value = event.get("timestamp")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"event timestamp must be a string in {source}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"invalid event timestamp in {source}: {value}") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"event timestamp lacks timezone in {source}")
    return parsed


def _load_telemetry_dataset(
    dataset: Mapping[str, Any], path: str, bundle_root: Path
) -> Tuple[List[CorpusCase], DatasetMetadata]:
    data = _object(
        dataset, path, {"id", "kind", "description", "path", "sha256", "replay"}
    )
    dataset_id = _string(data["id"], f"{path}.id", maximum=96)
    source = resolve_inside(
        bundle_root, _string(data["path"], f"{path}.path", maximum=240)
    )
    try:
        source_size = source.stat().st_size
    except FileNotFoundError as exc:
        raise ValidationError(f"dataset file does not exist: {source}") from exc
    if source_size > MAX_TELEMETRY_BYTES:
        raise ValidationError(f"telemetry dataset exceeds size limit: {dataset_id}")
    expected_hash = _string(data["sha256"], f"{path}.sha256", maximum=64)
    actual_hash = file_sha256(source)
    if actual_hash != expected_hash:
        raise IntegrityError(f"dataset hash mismatch for {dataset_id}: {actual_hash}")
    replay = _boolean(data["replay"], f"{path}.replay")
    cases: List[CorpusCase] = []
    try:
        with source.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                if len(line.encode("utf-8")) > MAX_EVENT_BYTES:
                    raise ValidationError(
                        f"telemetry event exceeds size limit: {source}:{line_number}"
                    )
                raw = loads_json(line, f"{source}:{line_number}")
                event = _object(
                    raw,
                    f"{source}:{line_number}",
                    {"event_id"},
                    set(raw) - {"event_id"},
                )
                event_id = _string(
                    event["event_id"],
                    f"{source}:{line_number}.event_id",
                    maximum=160,
                )
                cases.append(
                    CorpusCase(
                        id=f"{dataset_id}:{event_id}",
                        dataset_id=dataset_id,
                        kind="event",
                        replay=replay,
                        payload=dict(event),
                        timestamp=_timestamp(event, str(source)),
                        source_path=source,
                    )
                )
    except UnicodeDecodeError as exc:
        raise ValidationError(f"telemetry dataset is not UTF-8: {dataset_id}") from exc
    if not cases:
        raise ValidationError(f"telemetry dataset is empty: {dataset_id}")
    return cases, DatasetMetadata(
        id=dataset_id,
        kind="telemetry-jsonl",
        description=_string(data["description"], f"{path}.description", maximum=500),
        replay=replay,
        case_count=len(cases),
        source_path=str(data["path"]),
        sha256=actual_hash,
    )


def _load_artifact_dataset(
    dataset: Mapping[str, Any], path: str, bundle_root: Path
) -> Tuple[List[CorpusCase], DatasetMetadata]:
    data = _object(dataset, path, {"id", "kind", "description", "cases"})
    dataset_id = _string(data["id"], f"{path}.id", maximum=96)
    raw_cases = data["cases"]
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValidationError(f"{path}.cases must be a non-empty list")
    cases: List[CorpusCase] = []
    combined_material = bytearray()
    for index, raw_case in enumerate(raw_cases):
        case_path = f"{path}.cases[{index}]"
        case_data = _object(raw_case, case_path, {"id", "path", "sha256", "replay"})
        case_id = _string(case_data["id"], f"{case_path}.id", maximum=96)
        source = resolve_inside(
            bundle_root, _string(case_data["path"], f"{case_path}.path", maximum=240)
        )
        try:
            source_size = source.stat().st_size
        except FileNotFoundError as exc:
            raise ValidationError(f"artifact does not exist: {source}") from exc
        if source_size > MAX_ARTIFACT_BYTES:
            raise ValidationError(
                f"artifact exceeds size limit: {dataset_id}:{case_id}"
            )
        expected_hash = _string(case_data["sha256"], f"{case_path}.sha256", maximum=64)
        actual_hash = file_sha256(source)
        if actual_hash != expected_hash:
            raise IntegrityError(f"artifact hash mismatch for {dataset_id}:{case_id}")
        payload = source.read_bytes()
        combined_material.extend(actual_hash.encode("ascii"))
        cases.append(
            CorpusCase(
                id=f"{dataset_id}:{case_id}",
                dataset_id=dataset_id,
                kind="artifact",
                replay=_boolean(case_data["replay"], f"{case_path}.replay"),
                payload=payload,
                timestamp=None,
                source_path=source,
            )
        )
    combined_hash = hashlib.sha256(combined_material).hexdigest()
    return cases, DatasetMetadata(
        id=dataset_id,
        kind="artifact",
        description=_string(data["description"], f"{path}.description", maximum=500),
        replay=any(item.replay for item in cases),
        case_count=len(cases),
        source_path="multiple integrity-pinned artifacts",
        sha256=combined_hash,
    )


def load_corpus(
    bundle_root: Path,
) -> Tuple[Tuple[CorpusCase, ...], Tuple[DatasetMetadata, ...]]:
    index_path = bundle_root / "datasets" / "index.json"
    raw = load_json(index_path)
    data = _object(raw, "$", {"version", "datasets"})
    if data["version"] != "1.0":
        raise ValidationError(f"unsupported corpus index version: {data['version']}")
    datasets = data["datasets"]
    if not isinstance(datasets, list) or not datasets:
        raise ValidationError("corpus index must declare datasets")
    all_cases: List[CorpusCase] = []
    metadata: List[DatasetMetadata] = []
    for index, dataset in enumerate(datasets):
        path = f"$.datasets[{index}]"
        if not isinstance(dataset, Mapping):
            raise ValidationError(f"{path} must be an object")
        kind = dataset.get("kind")
        if kind == "telemetry-jsonl":
            cases, item_metadata = _load_telemetry_dataset(dataset, path, bundle_root)
        elif kind == "artifact":
            cases, item_metadata = _load_artifact_dataset(dataset, path, bundle_root)
        else:
            raise ValidationError(f"unsupported dataset kind at {path}: {kind}")
        all_cases.extend(cases)
        metadata.append(item_metadata)
    ids = [item.id for item in all_cases]
    if len(set(ids)) != len(ids):
        raise ValidationError("corpus case identifiers must be globally unique")
    dataset_ids = [item.id for item in metadata]
    if len(set(dataset_ids)) != len(dataset_ids):
        raise ValidationError("dataset identifiers must be unique")
    return tuple(all_cases), tuple(metadata)


def verify_provenance(
    bundle_root: Path, upstream_root: Path | None = None
) -> Dict[str, Any]:
    provenance_path = (
        bundle_root / "datasets" / "autonomous-payroll" / "provenance.json"
    )
    raw = load_json(provenance_path)
    data = _object(
        raw,
        "$",
        {
            "contract_version",
            "source_project",
            "source_repository",
            "source_scenario",
            "imported_at",
            "upstream_files",
            "vendored_files",
            "canonical_report_sha256",
        },
    )
    if data["contract_version"] != "1.0":
        raise ValidationError("unsupported integration provenance contract")
    vendored = _object(
        data["vendored_files"], "$.vendored_files", {"report.json", "telemetry.jsonl"}
    )
    checks: Dict[str, bool] = {}
    for filename, expected in vendored.items():
        target = provenance_path.parent / filename
        if not target.is_file():
            raise IntegrityError(f"vendored integration file is missing: {filename}")
        checks[f"vendored:{filename}"] = file_sha256(target) == expected
    if upstream_root is not None:
        upstream = _object(
            data["upstream_files"],
            "$.upstream_files",
            {"report.json", "telemetry.jsonl"},
        )
        for filename, expected in upstream.items():
            if not (upstream_root / filename).is_file():
                raise IntegrityError(
                    f"upstream integration file is missing: {filename}"
                )
            checks[f"upstream:{filename}"] = (
                file_sha256(upstream_root / filename) == expected
            )
    if not all(checks.values()):
        failed = ", ".join(key for key, passed in checks.items() if not passed)
        raise IntegrityError(f"integration provenance failed: {failed}")
    return {
        "valid": True,
        "checks": checks,
        "source_project": data["source_project"],
        "source_repository": data["source_repository"],
        "source_scenario": data["source_scenario"],
        "canonical_report_sha256": data["canonical_report_sha256"],
    }
