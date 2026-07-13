"""Immutable domain models shared by validators, engines, and replay."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Tuple


class EngineKind(str, Enum):
    SIGMA = "sigma"
    YARA = "yara"
    FALCO = "falco"


class RuleState(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    CANARY = "canary"
    PRODUCTION = "production"
    QUARANTINED = "quarantined"
    RETIRED = "retired"


class ExpectedDecision(str, Enum):
    PROMOTE = "PROMOTE"
    HOLD = "HOLD"
    REJECT = "REJECT"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


@dataclass(frozen=True)
class ThreatCoverage:
    summary: str
    severity: str
    techniques: Tuple[Technique, ...]


@dataclass(frozen=True)
class RuleTests:
    positive_cases: Tuple[str, ...]
    negative_cases: Tuple[str, ...]


@dataclass(frozen=True)
class PerformanceBudget:
    min_precision: float
    min_recall: float
    max_false_positive_rate: float
    max_p95_latency_ms: float
    max_alerts_per_100: float


@dataclass(frozen=True)
class Lifecycle:
    current_state: RuleState
    requested_state: RuleState
    canary_percent: int
    expected_decision: ExpectedDecision


@dataclass(frozen=True)
class RuleChange:
    revision: int
    changed_at: date
    changed_by: str
    summary: str
    source_sha256: str


@dataclass(frozen=True)
class RuleManifest:
    api_version: str
    kind: str
    id: str
    title: str
    owner: str
    description: str
    created_at: date
    modified_at: date
    expires_at: date
    revision: int
    status: str
    engine: EngineKind
    source: str
    entrypoint: str | None
    threat: ThreatCoverage
    tests: RuleTests
    performance: PerformanceBudget
    lifecycle: Lifecycle
    change_history: Tuple[RuleChange, ...]
    manifest_path: Path
    source_path: Path
    source_sha256: str


@dataclass(frozen=True)
class CorpusCase:
    id: str
    dataset_id: str
    kind: str
    replay: bool
    payload: Any
    timestamp: datetime | None
    source_path: Path


@dataclass(frozen=True)
class DatasetMetadata:
    id: str
    kind: str
    description: str
    replay: bool
    case_count: int
    source_path: str
    sha256: str | None


def iso_datetime(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def to_jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return iso_datetime(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [to_jsonable(item) for item in value]
    return value
