"""Historical replay, quality metrics, diagnostics, and lifecycle policy."""

from __future__ import annotations

import math
import platform
import statistics
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Set, Tuple

from . import __version__
from .audit import build_audit_chain, verify_audit_chain
from .corpus import load_corpus, verify_provenance
from .engines import RuleMatcher, compile_rule
from .errors import ValidationError
from .manifest import load_manifests, public_manifest
from .models import CorpusCase, ExpectedDecision, RuleManifest, RuleState, to_jsonable
from .serialization import digest


@dataclass
class _EvaluatedRule:
    manifest: RuleManifest
    matcher: RuleMatcher
    unit_results: List[Dict[str, Any]]
    matched_case_ids: Set[str]
    replay_case_ids: Set[str]
    true_positive_ids: Set[str]
    latencies_ms: List[float]
    metrics: Dict[str, Any]
    diagnostics: Set[str]


def _p95(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1))
    return ordered[rank]


def _evaluate_tests(
    manifest: RuleManifest, matcher: RuleMatcher, cases: Mapping[str, CorpusCase]
) -> List[Dict[str, Any]]:
    results = []
    for expected, identifiers in (
        (True, manifest.tests.positive_cases),
        (False, manifest.tests.negative_cases),
    ):
        for case_id in identifiers:
            if case_id not in cases:
                raise ValidationError(
                    f"rule {manifest.id} references unknown test case: {case_id}"
                )
            case = cases[case_id]
            if case.kind != matcher.case_kind:
                raise ValidationError(
                    f"rule {manifest.id} test case {case_id} has kind {case.kind}, expected {matcher.case_kind}"
                )
            actual = matcher.match(case)
            results.append(
                {
                    "case_id": case_id,
                    "expected": expected,
                    "actual": actual,
                    "passed": actual is expected,
                }
            )
    return results


def _evaluate_rule(
    manifest: RuleManifest, cases: Mapping[str, CorpusCase], as_of: date
) -> _EvaluatedRule:
    matcher = compile_rule(manifest)
    unit_results = _evaluate_tests(manifest, matcher, cases)
    replay_cases = sorted(
        (
            case
            for case in cases.values()
            if case.replay and case.kind == matcher.case_kind
        ),
        key=lambda item: item.id,
    )
    matched: Set[str] = set()
    latencies: List[float] = []
    for case in replay_cases:
        started = time.perf_counter_ns()
        did_match = matcher.match(case)
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        if did_match:
            matched.add(case.id)

    replay_ids = {case.id for case in replay_cases}
    expected_positive = set(manifest.tests.positive_cases) & replay_ids
    expected_negative = replay_ids - expected_positive
    true_positives = matched & expected_positive
    false_positives = matched & expected_negative
    false_negatives = expected_positive - matched
    true_negatives = expected_negative - matched
    precision = (
        len(true_positives) / (len(true_positives) + len(false_positives))
        if true_positives or false_positives
        else None
    )
    recall = (
        len(true_positives) / (len(true_positives) + len(false_negatives))
        if true_positives or false_negatives
        else None
    )
    false_positive_rate = (
        len(false_positives) / (len(false_positives) + len(true_negatives))
        if false_positives or true_negatives
        else 0.0
    )
    alerts_per_100 = len(matched) / len(replay_cases) * 100 if replay_cases else 0.0
    p95_latency = _p95(latencies)
    diagnostics: Set[str] = set()
    if not matched:
        diagnostics.add("silent")
    if false_positive_rate > manifest.performance.max_false_positive_rate or (
        alerts_per_100 > manifest.performance.max_alerts_per_100
    ):
        diagnostics.add("noisy")
    if precision is not None and precision < manifest.performance.min_precision:
        diagnostics.add("under_precision")
    if recall is not None and recall < manifest.performance.min_recall:
        diagnostics.add("under_recall")
    if p95_latency > manifest.performance.max_p95_latency_ms:
        diagnostics.add("latency_budget_exceeded")
    if manifest.expires_at < as_of:
        diagnostics.add("expired")
    if not all(item["passed"] for item in unit_results):
        diagnostics.add("unit_test_failure")
    metrics = {
        "true_positives": len(true_positives),
        "false_positives": len(false_positives),
        "true_negatives": len(true_negatives),
        "false_negatives": len(false_negatives),
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "alerts_per_100_cases": alerts_per_100,
        "alert_count": len(matched),
        "replay_case_count": len(replay_cases),
        "latency_ms": {
            "min": round(min(latencies), 6) if latencies else 0.0,
            "median": round(statistics.median(latencies), 6) if latencies else 0.0,
            "p95": round(p95_latency, 6),
            "max": round(max(latencies), 6) if latencies else 0.0,
        },
    }
    return _EvaluatedRule(
        manifest=manifest,
        matcher=matcher,
        unit_results=unit_results,
        matched_case_ids=matched,
        replay_case_ids=replay_ids,
        true_positive_ids=expected_positive,
        latencies_ms=latencies,
        metrics=metrics,
        diagnostics=diagnostics,
    )


def _redundancy(evaluated: Sequence[_EvaluatedRule]) -> List[Dict[str, Any]]:
    state_rank = {
        RuleState.PRODUCTION: 5,
        RuleState.CANARY: 4,
        RuleState.VALIDATED: 3,
        RuleState.DRAFT: 2,
        RuleState.QUARANTINED: 1,
        RuleState.RETIRED: 0,
    }
    pairs = []
    for left_index, left in enumerate(evaluated):
        for right in evaluated[left_index + 1 :]:
            if left.matcher.case_kind != right.matcher.case_kind:
                continue
            union = left.matched_case_ids | right.matched_case_ids
            if not union:
                continue
            similarity = len(left.matched_case_ids & right.matched_case_ids) / len(
                union
            )
            technique_overlap = {
                item.id for item in left.manifest.threat.techniques
            } & {item.id for item in right.manifest.threat.techniques}
            if similarity >= 0.8 and technique_overlap:
                candidates = sorted(
                    (left, right),
                    key=lambda item: (
                        -state_rank[item.manifest.lifecycle.current_state],
                        item.manifest.id,
                    ),
                )
                keeper, redundant = candidates
                pairs.append(
                    {
                        "left_rule_id": left.manifest.id,
                        "right_rule_id": right.manifest.id,
                        "alert_jaccard": round(similarity, 6),
                        "shared_techniques": sorted(technique_overlap),
                        "preferred_rule_id": keeper.manifest.id,
                        "redundant_rule_id": redundant.manifest.id,
                    }
                )
                redundant.diagnostics.add("redundant")
    return pairs


def _decision(rule: _EvaluatedRule) -> Tuple[ExpectedDecision, RuleState, List[str]]:
    diagnostics = rule.diagnostics
    rejection = {
        "expired",
        "noisy",
        "under_precision",
        "under_recall",
        "unit_test_failure",
    }
    if diagnostics & rejection:
        return (
            ExpectedDecision.REJECT,
            RuleState.QUARANTINED,
            sorted(diagnostics & rejection),
        )
    if diagnostics & {"silent", "redundant", "latency_budget_exceeded"}:
        return (
            ExpectedDecision.HOLD,
            rule.manifest.lifecycle.current_state,
            sorted(diagnostics),
        )
    return (
        ExpectedDecision.PROMOTE,
        rule.manifest.lifecycle.requested_state,
        ["all deterministic gates passed"],
    )


def _rule_report(rule: _EvaluatedRule) -> Dict[str, Any]:
    decision, resulting_state, reasons = _decision(rule)
    expected = rule.manifest.lifecycle.expected_decision
    rule_data = public_manifest(rule.manifest)
    return {
        "rule": rule_data,
        "unit_tests": rule.unit_results,
        "metrics": rule.metrics,
        "matched_case_ids": sorted(rule.matched_case_ids),
        "diagnostics": sorted(rule.diagnostics),
        "lifecycle": {
            "decision": decision.value,
            "expected_decision": expected.value,
            "expectation_met": decision is expected,
            "previous_state": rule.manifest.lifecycle.current_state.value,
            "requested_state": rule.manifest.lifecycle.requested_state.value,
            "resulting_state": resulting_state.value,
            "reasons": reasons,
            "deployment_effect": "simulation-only",
        },
    }


def _functional_view(report: Mapping[str, Any]) -> Dict[str, Any]:
    engine = dict(report["engine"])
    engine.pop("python", None)
    rules = []
    for item in report["rules"]:
        rule = dict(item)
        metrics = dict(rule["metrics"])
        metrics.pop("latency_ms", None)
        rule["metrics"] = metrics
        rules.append(rule)
    return {
        "report_version": report["report_version"],
        "engine": engine,
        "as_of": report["as_of"],
        "historical_window": report["historical_window"],
        "provenance": report["provenance"],
        "datasets": report["datasets"],
        "summary": report["summary"],
        "coverage": report["coverage"],
        "diagnostics": report["diagnostics"],
        "rules": rules,
        "audit": report["audit"],
    }


def run_replay(bundle_root: Path, as_of: date) -> Dict[str, Any]:
    started = time.perf_counter_ns()
    provenance = verify_provenance(bundle_root)
    cases, datasets = load_corpus(bundle_root)
    case_map = {case.id: case for case in cases}
    manifests = load_manifests(bundle_root)
    evaluated = [_evaluate_rule(manifest, case_map, as_of) for manifest in manifests]
    redundancy_pairs = _redundancy(evaluated)
    rule_reports = [_rule_report(item) for item in evaluated]
    techniques = sorted(
        {
            technique.id
            for item in evaluated
            for technique in item.manifest.threat.techniques
        }
    )
    promoted_techniques = sorted(
        {
            technique.id
            for item, rendered in zip(evaluated, rule_reports)
            if rendered["lifecycle"]["decision"] == ExpectedDecision.PROMOTE.value
            for technique in item.manifest.threat.techniques
        }
    )
    all_event_times = sorted(
        case.timestamp for case in cases if case.replay and case.timestamp is not None
    )
    audit_events: List[Dict[str, Any]] = []
    for item, rendered in zip(evaluated, rule_reports):
        audit_events.append(
            {
                "event_type": "rule_revision_loaded",
                "rule_id": item.manifest.id,
                "revision": item.manifest.revision,
                "source_sha256": item.manifest.source_sha256,
                "change_history_sha256": digest(
                    to_jsonable(item.manifest.change_history)
                ),
                "actor": "deterministic-policy-engine",
            }
        )
        audit_events.append(
            {
                "event_type": "lifecycle_decision",
                "rule_id": item.manifest.id,
                "decision": rendered["lifecycle"]["decision"],
                "previous_state": rendered["lifecycle"]["previous_state"],
                "resulting_state": rendered["lifecycle"]["resulting_state"],
                "evidence_sha256": digest(
                    {
                        "unit_tests": rendered["unit_tests"],
                        "functional_metrics": {
                            key: value
                            for key, value in rendered["metrics"].items()
                            if key != "latency_ms"
                        },
                        "diagnostics": rendered["diagnostics"],
                    }
                ),
                "actor": "deterministic-policy-engine",
            }
        )
    audit = build_audit_chain(as_of, audit_events)
    verify_audit_chain(audit)
    report: Dict[str, Any] = {
        "report_version": "1.0",
        "engine": {
            "name": "detection-as-code-platform",
            "version": __version__,
            "python": platform.python_version(),
            "execution_profiles": {
                "sigma": "documented-event-subset/v1",
                "falco": "documented-filter-subset/v1",
                "yara": "yara-python/4.5.4",
            },
        },
        "as_of": as_of.isoformat(),
        "historical_window": {
            "start": all_event_times[0].isoformat().replace("+00:00", "Z")
            if all_event_times
            else None,
            "end": all_event_times[-1].isoformat().replace("+00:00", "Z")
            if all_event_times
            else None,
        },
        "provenance": provenance,
        "datasets": to_jsonable(datasets),
        "summary": {
            "rule_count": len(evaluated),
            "replay_case_count": len({case.id for case in cases if case.replay}),
            "unit_test_count": sum(len(item.unit_results) for item in evaluated),
            "unit_test_pass_rate": sum(
                result["passed"] for item in evaluated for result in item.unit_results
            )
            / sum(len(item.unit_results) for item in evaluated),
            "promote_count": sum(
                item["lifecycle"]["decision"] == ExpectedDecision.PROMOTE.value
                for item in rule_reports
            ),
            "hold_count": sum(
                item["lifecycle"]["decision"] == ExpectedDecision.HOLD.value
                for item in rule_reports
            ),
            "reject_count": sum(
                item["lifecycle"]["decision"] == ExpectedDecision.REJECT.value
                for item in rule_reports
            ),
            "all_expected_decisions_met": all(
                item["lifecycle"]["expectation_met"] for item in rule_reports
            ),
        },
        "coverage": {
            "declared_mitre_techniques": techniques,
            "promotable_mitre_techniques": promoted_techniques,
            "promotable_technique_ratio": len(promoted_techniques) / len(techniques)
            if techniques
            else 0.0,
            "engines": sorted({item.manifest.engine.value for item in evaluated}),
        },
        "diagnostics": {
            "silent_rules": sorted(
                item.manifest.id for item in evaluated if "silent" in item.diagnostics
            ),
            "noisy_rules": sorted(
                item.manifest.id for item in evaluated if "noisy" in item.diagnostics
            ),
            "redundant_pairs": redundancy_pairs,
            "expired_rules": sorted(
                item.manifest.id for item in evaluated if "expired" in item.diagnostics
            ),
        },
        "rules": rule_reports,
        "audit": audit,
        "measurement": {
            "wall_clock_latency_ms": round(
                (time.perf_counter_ns() - started) / 1_000_000, 6
            ),
            "latency_is_environment_dependent": True,
        },
    }
    report["functional_sha256"] = digest(_functional_view(report))
    return report


def functional_view(report: Mapping[str, Any]) -> Dict[str, Any]:
    return _functional_view(report)
