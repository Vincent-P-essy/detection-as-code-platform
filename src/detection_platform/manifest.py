"""Strict parser for versioned detection rule manifests."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Any, Mapping, Set, Tuple, cast

from .bundle import resolve_inside
from .errors import IntegrityError, ValidationError
from .models import (
    EngineKind,
    ExpectedDecision,
    Lifecycle,
    PerformanceBudget,
    RuleChange,
    RuleManifest,
    RuleState,
    RuleTests,
    Technique,
    ThreatCoverage,
    to_jsonable,
)
from .serialization import file_sha256
from .yamlutil import load_yaml


API_VERSION = "detection.platform/v1"
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
_TECHNIQUE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


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
        raise ValidationError(
            f"{path} must be a non-empty string up to {maximum} characters"
        )
    return value.strip()


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ValidationError(
            f"{path} must be an integer between {minimum} and {maximum}"
        )
    return int(value)


def _number(value: Any, path: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{path} must be numeric")
    parsed = float(value)
    if not minimum <= parsed <= maximum:
        raise ValidationError(f"{path} must be between {minimum} and {maximum}")
    return parsed


def _date(value: Any, path: str) -> date:
    if isinstance(value, date):
        return value
    text = _string(value, path, maximum=10)
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(f"{path} must be an ISO date") from exc


def _strings(value: Any, path: str, minimum: int = 1) -> Tuple[str, ...]:
    if not isinstance(value, list) or len(value) < minimum:
        raise ValidationError(f"{path} must contain at least {minimum} values")
    parsed = tuple(
        _string(item, f"{path}[{index}]", maximum=180)
        for index, item in enumerate(value)
    )
    if len(set(parsed)) != len(parsed):
        raise ValidationError(f"{path} must not contain duplicates")
    return parsed


def _parse_techniques(value: Any) -> Tuple[Technique, ...]:
    if not isinstance(value, list) or not value:
        raise ValidationError("$.spec.threat.techniques must be a non-empty list")
    result = []
    for index, raw in enumerate(value):
        path = f"$.spec.threat.techniques[{index}]"
        data = _object(raw, path, {"id", "name", "tactic"})
        technique_id = _string(data["id"], f"{path}.id", maximum=16)
        if not _TECHNIQUE.fullmatch(technique_id):
            raise ValidationError(
                f"invalid ATT&CK technique identifier: {technique_id}"
            )
        result.append(
            Technique(
                id=technique_id,
                name=_string(data["name"], f"{path}.name", maximum=120),
                tactic=_string(data["tactic"], f"{path}.tactic", maximum=64),
            )
        )
    if len({item.id for item in result}) != len(result):
        raise ValidationError("technique identifiers must be unique")
    return tuple(result)


def _parse_history(
    value: Any,
    current_revision: int,
    created_at: date,
    modified_at: date,
    current_source_hash: str,
) -> Tuple[RuleChange, ...]:
    if not isinstance(value, list) or not value:
        raise ValidationError("$.history must be a non-empty list")
    result = []
    for index, raw in enumerate(value):
        path = f"$.history[{index}]"
        data = _object(
            raw,
            path,
            {"revision", "changed_at", "changed_by", "summary", "source_sha256"},
        )
        source_hash = _string(
            data["source_sha256"], f"{path}.source_sha256", maximum=64
        )
        if not _SHA256.fullmatch(source_hash):
            raise ValidationError(f"{path}.source_sha256 must be a lowercase SHA-256")
        result.append(
            RuleChange(
                revision=_integer(data["revision"], f"{path}.revision", 1, 1_000_000),
                changed_at=_date(data["changed_at"], f"{path}.changed_at"),
                changed_by=_string(
                    data["changed_by"], f"{path}.changed_by", maximum=160
                ),
                summary=_string(data["summary"], f"{path}.summary", maximum=500),
                source_sha256=source_hash,
            )
        )
    revisions = [item.revision for item in result]
    if (
        revisions != list(range(1, len(revisions) + 1))
        or revisions[-1] != current_revision
    ):
        raise ValidationError("change history must contain each revision in order")
    dates = [item.changed_at for item in result]
    if dates != sorted(dates) or dates[0] < created_at or dates[-1] != modified_at:
        raise ValidationError(
            "change history dates must be ordered and end at modified_at"
        )
    if result[-1].source_sha256 != current_source_hash:
        raise IntegrityError("latest change history hash does not match rule source")
    return tuple(result)


def load_manifest(path: Path, bundle_root: Path) -> RuleManifest:
    raw = load_yaml(path)
    data = _object(raw, "$", {"api_version", "kind", "metadata", "spec", "history"})
    api_version = _string(data["api_version"], "$.api_version", maximum=64)
    if api_version != API_VERSION:
        raise ValidationError(f"unsupported rule API version: {api_version}")
    kind = _string(data["kind"], "$.kind", maximum=64)
    if kind != "DetectionRule":
        raise ValidationError(f"unsupported manifest kind: {kind}")

    metadata = _object(
        data["metadata"],
        "$.metadata",
        {
            "id",
            "title",
            "owner",
            "description",
            "created_at",
            "modified_at",
            "expires_at",
            "revision",
            "status",
        },
    )
    rule_id = _string(metadata["id"], "$.metadata.id", maximum=96)
    if not _ID.fullmatch(rule_id):
        raise ValidationError(
            "rule id must use lowercase letters, digits, dots, dashes, or underscores"
        )
    created_at = _date(metadata["created_at"], "$.metadata.created_at")
    modified_at = _date(metadata["modified_at"], "$.metadata.modified_at")
    expires_at = _date(metadata["expires_at"], "$.metadata.expires_at")
    if not created_at <= modified_at < expires_at:
        raise ValidationError(
            "rule dates must satisfy created_at <= modified_at < expires_at"
        )

    spec = _object(
        data["spec"],
        "$.spec",
        {
            "engine",
            "source",
            "source_sha256",
            "threat",
            "tests",
            "performance",
            "lifecycle",
        },
        {"entrypoint"},
    )
    try:
        engine = EngineKind(_string(spec["engine"], "$.spec.engine", maximum=16))
    except ValueError as exc:
        raise ValidationError("engine must be sigma, yara, or falco") from exc
    source = _string(spec["source"], "$.spec.source", maximum=240)
    source_path = resolve_inside(bundle_root, source)
    if not source_path.is_file():
        raise ValidationError(f"rule source does not exist: {source}")
    if source_path.stat().st_size > 262_144:
        raise ValidationError(f"rule source exceeds 262144 bytes: {source}")
    expected_source_hash = _string(
        spec["source_sha256"], "$.spec.source_sha256", maximum=64
    )
    if not _SHA256.fullmatch(expected_source_hash):
        raise ValidationError("spec.source_sha256 must be a lowercase SHA-256")
    actual_source_hash = file_sha256(source_path)
    if actual_source_hash != expected_source_hash:
        raise IntegrityError(f"rule source hash mismatch: {source}")
    expected_suffix = {
        EngineKind.SIGMA: ".yml",
        EngineKind.FALCO: ".yml",
        EngineKind.YARA: ".yar",
    }[engine]
    if source_path.suffix != expected_suffix:
        raise ValidationError(
            f"{engine.value} rule source must end in {expected_suffix}"
        )
    entrypoint_raw = spec.get("entrypoint")
    entrypoint = (
        _string(entrypoint_raw, "$.spec.entrypoint", maximum=128)
        if entrypoint_raw
        else None
    )
    if engine is EngineKind.YARA and entrypoint is None:
        raise ValidationError("YARA manifests require spec.entrypoint")
    if engine is not EngineKind.YARA and entrypoint is not None:
        raise ValidationError("spec.entrypoint is supported only for YARA")

    threat_data = _object(
        spec["threat"], "$.spec.threat", {"summary", "severity", "techniques"}
    )
    severity = _string(threat_data["severity"], "$.spec.threat.severity", maximum=16)
    if severity not in {"low", "medium", "high", "critical"}:
        raise ValidationError("threat severity must be low, medium, high, or critical")
    threat = ThreatCoverage(
        summary=_string(threat_data["summary"], "$.spec.threat.summary", maximum=500),
        severity=severity,
        techniques=_parse_techniques(threat_data["techniques"]),
    )

    tests_data = _object(
        spec["tests"], "$.spec.tests", {"positive_cases", "negative_cases"}
    )
    tests = RuleTests(
        positive_cases=_strings(
            tests_data["positive_cases"], "$.spec.tests.positive_cases"
        ),
        negative_cases=_strings(
            tests_data["negative_cases"], "$.spec.tests.negative_cases"
        ),
    )
    if set(tests.positive_cases) & set(tests.negative_cases):
        raise ValidationError("positive and negative test cases must be disjoint")

    performance_data = _object(
        spec["performance"],
        "$.spec.performance",
        {
            "min_precision",
            "min_recall",
            "max_false_positive_rate",
            "max_p95_latency_ms",
            "max_alerts_per_100",
        },
    )
    performance = PerformanceBudget(
        min_precision=_number(
            performance_data["min_precision"], "$.spec.performance.min_precision", 0, 1
        ),
        min_recall=_number(
            performance_data["min_recall"], "$.spec.performance.min_recall", 0, 1
        ),
        max_false_positive_rate=_number(
            performance_data["max_false_positive_rate"],
            "$.spec.performance.max_false_positive_rate",
            0,
            1,
        ),
        max_p95_latency_ms=_number(
            performance_data["max_p95_latency_ms"],
            "$.spec.performance.max_p95_latency_ms",
            0.001,
            60_000,
        ),
        max_alerts_per_100=_number(
            performance_data["max_alerts_per_100"],
            "$.spec.performance.max_alerts_per_100",
            0,
            100,
        ),
    )

    lifecycle_data = _object(
        spec["lifecycle"],
        "$.spec.lifecycle",
        {"current_state", "requested_state", "canary_percent", "expected_decision"},
    )
    try:
        lifecycle = Lifecycle(
            current_state=RuleState(
                _string(
                    lifecycle_data["current_state"],
                    "$.spec.lifecycle.current_state",
                    maximum=24,
                )
            ),
            requested_state=RuleState(
                _string(
                    lifecycle_data["requested_state"],
                    "$.spec.lifecycle.requested_state",
                    maximum=24,
                )
            ),
            canary_percent=_integer(
                lifecycle_data["canary_percent"],
                "$.spec.lifecycle.canary_percent",
                1,
                100,
            ),
            expected_decision=ExpectedDecision(
                _string(
                    lifecycle_data["expected_decision"],
                    "$.spec.lifecycle.expected_decision",
                    maximum=16,
                )
            ),
        )
    except ValueError as exc:
        raise ValidationError(f"invalid lifecycle enumeration: {exc}") from exc

    revision = _integer(metadata["revision"], "$.metadata.revision", 1, 1_000_000)
    change_history = _parse_history(
        data["history"],
        revision,
        created_at,
        modified_at,
        actual_source_hash,
    )

    return RuleManifest(
        api_version=api_version,
        kind=kind,
        id=rule_id,
        title=_string(metadata["title"], "$.metadata.title", maximum=160),
        owner=_string(metadata["owner"], "$.metadata.owner", maximum=160),
        description=_string(
            metadata["description"], "$.metadata.description", maximum=800
        ),
        created_at=created_at,
        modified_at=modified_at,
        expires_at=expires_at,
        revision=revision,
        status=_string(metadata["status"], "$.metadata.status", maximum=32),
        engine=engine,
        source=source,
        entrypoint=entrypoint,
        threat=threat,
        tests=tests,
        performance=performance,
        lifecycle=lifecycle,
        change_history=change_history,
        manifest_path=path,
        source_path=source_path,
        source_sha256=actual_source_hash,
    )


def load_manifests(bundle_root: Path) -> Tuple[RuleManifest, ...]:
    manifest_dir = bundle_root / "manifests"
    manifests = tuple(
        load_manifest(path, bundle_root) for path in sorted(manifest_dir.glob("*.yml"))
    )
    if not manifests:
        raise ValidationError("bundle contains no rule manifests")
    ids = [item.id for item in manifests]
    if len(set(ids)) != len(ids):
        raise ValidationError("rule manifest identifiers must be unique")
    return manifests


def public_manifest(manifest: RuleManifest) -> Mapping[str, Any]:
    """Render metadata without exposing host/container absolute paths."""

    data = cast(dict[str, Any], to_jsonable(manifest))
    data["manifest_path"] = f"manifests/{manifest.manifest_path.name}"
    data["source_path"] = manifest.source
    return data
