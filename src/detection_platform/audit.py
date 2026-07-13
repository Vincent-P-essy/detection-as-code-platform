"""Deterministic tamper-evident audit-chain construction and verification."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from .errors import IntegrityError
from .serialization import digest


GENESIS_HASH = "0" * 64


def build_audit_chain(
    as_of: date, events: Sequence[Mapping[str, Any]]
) -> List[Dict[str, Any]]:
    previous_hash = GENESIS_HASH
    base = datetime(as_of.year, as_of.month, as_of.day, tzinfo=timezone.utc)
    entries: List[Dict[str, Any]] = []
    for index, event in enumerate(events, start=1):
        body: Dict[str, Any] = {
            "sequence": index,
            "timestamp": (base + timedelta(seconds=index))
            .isoformat()
            .replace("+00:00", "Z"),
            "previous_hash": previous_hash,
            **dict(event),
        }
        body["entry_hash"] = digest(body)
        previous_hash = body["entry_hash"]
        entries.append(body)
    return entries


def verify_audit_chain(entries: Iterable[Mapping[str, Any]]) -> bool:
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    for entry in entries:
        if entry.get("sequence") != expected_sequence:
            raise IntegrityError("audit sequence is not contiguous")
        if entry.get("previous_hash") != previous_hash:
            raise IntegrityError("audit previous-hash link is invalid")
        claimed = entry.get("entry_hash")
        unsigned = {key: value for key, value in entry.items() if key != "entry_hash"}
        actual = digest(unsigned)
        if claimed != actual:
            raise IntegrityError("audit entry hash is invalid")
        previous_hash = actual
        expected_sequence += 1
    return True
