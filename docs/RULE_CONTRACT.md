# Rule contract and review workflow

## Versioned manifest

`detection.platform/v1` is a closed YAML contract. Unknown keys are errors. A
minimal shape is:

```yaml
api_version: detection.platform/v1
kind: DetectionRule
metadata:
  id: sigma.example
  title: Example rule
  owner: detection-team@example.invalid
  description: A reviewable threat hypothesis.
  created_at: 2026-07-13
  modified_at: 2026-07-13
  expires_at: 2027-07-13
  revision: 1
  status: test
spec:
  engine: sigma
  source: rules/sigma/example.yml
  source_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  threat:
    summary: The behavior being detected.
    severity: high
    techniques:
      - id: T1005
        name: Data from Local System
        tactic: collection
  tests:
    positive_cases: [dataset:positive-id]
    negative_cases: [dataset:negative-id]
  performance:
    min_precision: 0.95
    min_recall: 0.90
    max_false_positive_rate: 0.01
    max_p95_latency_ms: 5.0
    max_alerts_per_100: 5.0
  lifecycle:
    current_state: canary
    requested_state: production
    canary_percent: 10
    expected_decision: PROMOTE
history:
  - revision: 1
    changed_at: 2026-07-13
    changed_by: detection-team@example.invalid
    summary: Initial reviewed rule and tests.
    source_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

YARA additionally requires `spec.entrypoint`. Dates must satisfy
`created_at <= modified_at < expires_at`. Test lists must be non-empty, unique,
disjoint, globally resolvable, and compatible with the engine's case kind. History
must contain every revision in order; its final date and source hash must match the
current metadata and pinned source.

## Review checklist

1. Confirm the owner and threat hypothesis are actionable.
2. Verify the source semantics are inside the documented engine profile.
3. Review ATT&CK mappings as claims, not automatically inferred facts.
4. Inspect positive and negative fixtures and challenge rule-scoped labels.
5. Justify budgets from a baseline rather than weakening them to pass.
6. Increment the revision and update `modified_at` on semantic changes.
7. Set a finite expiration so stale rules are re-evaluated.
8. Run validation, tests, replay, and snapshot gates.
9. Compare functional/report changes during code review.
10. Treat the resulting lifecycle decision as evidence only; production change
    control remains external.

## Deterministic policy precedence

1. Any rejection defect causes `REJECT` and simulated quarantine.
2. Otherwise any hold defect causes `HOLD` at the current state.
3. Otherwise the decision is `PROMOTE` to the requested state.

This precedence prevents a healthy-looking aggregate metric from masking a failed
test, expiration, or unacceptable false-positive rate.
