# Evaluation methodology

## Experimental question

Given a versioned rule, explicit unit fixtures, and a historical corpus, does the
rule meet its declared functional and performance budgets closely enough to pass a
simulated lifecycle gate?

## Corpus construction

The corpus has four datasets:

- byte-identical golden incident telemetry from `autonomous-incident-simulator`;
- an eight-event benign office baseline;
- two non-replay log fixtures used to expose historical silence;
- one inert suspicious and one benign artifact for official YARA evaluation.

There are 24 unique cases, of which 22 participate in replay. Hashes are checked
before parsing. Event identifiers are globally unique, and replay order is sorted
by identifier so input filesystem ordering cannot affect outcomes.

## Rule-scoped ground truth

Each rule declares its positive cases. Every other compatible replay case is a
negative for that rule. This is intentionally **rule-scoped**, not a claim that an
entire event is globally benign or malicious. For example, an incident event can
be negative for a payroll-read rule while remaining relevant to another threat.

Positive and negative unit cases are separately declared and must be disjoint.
Unit tests prove intended examples; replay measures behavior across the full
compatible corpus.

## Metrics

For each rule:

```text
precision = TP / (TP + FP), undefined when the rule emits no alerts
recall    = TP / (TP + FN), undefined when no positive replay cases exist
FPR       = FP / (FP + TN), zero when there are no evaluated negatives
alerts/100 = matched replay cases / compatible replay cases * 100
```

The report stores TP, FP, TN, FN, alert identifiers, alert count, min/median/p95/max
match latency, and the aggregate metrics. P95 uses the nearest-rank method.

The dataset is deliberately small, so these numbers demonstrate an executable
measurement pipeline rather than statistically representative production quality.

## Diagnostics

- **silent:** no historical replay case matched;
- **noisy:** FPR or alert volume exceeds the rule budget;
- **under_precision / under_recall:** functional metric misses its budget;
- **latency_budget_exceeded:** measured p95 exceeds its budget;
- **expired:** `expires_at` precedes the explicit assessment date;
- **unit_test_failure:** at least one declared example behaves incorrectly;
- **redundant:** alert-set Jaccard is at least 0.8 with ATT&CK overlap and another
  candidate is deterministically preferred.

## Latency measurement

`perf_counter_ns()` surrounds each individual matcher invocation after compilation.
Reported timings therefore exclude file I/O, parsing, compilation, export, and HTTP
transport. They include Python dispatch and the matcher runtime. The full replay
also reports wall-clock latency.

Timings are environment-dependent and are not included in the functional digest.
The committed snapshot preserves one real run, but CI reproduces only functional
decisions and integrity—not exact nanosecond values. No throughput, concurrency,
or SIEM ingestion claim is made.

## Reproducibility

Functional reproducibility is provided by:

- pinned source and dataset hashes;
- exact runtime dependencies and pinned build dependencies;
- sorted manifests/cases and a fixed assessment date;
- deterministic diagnostic ordering, policy, audit events, and JSON encoding;
- a functional SHA-256 that excludes only environment-dependent measurements and
  the Python runtime version while retaining the executable engine profiles;
- a committed snapshot manifest with hashes of every exported file;
- CI that reruns the replay twice and reproduces the functional digest.

Run:

```bash
python scripts/quality_gate.py
python scripts/verify_snapshot.py
```

## Executable grammar

### Sigma profile v1

The parser accepts a single rule with an allowlisted top-level structure, a
non-empty `logsource`, named mapping selections, and a boolean `condition`.
Selections are conjunctions of field clauses. List values are alternatives.
Supported field modes are exact (default), `contains`, `startswith`, and
`endswith`; conditions support `and`, `or`, `not`, and parentheses.

Quantifiers (`1 of`), correlation, aggregation, wildcard expansion, regular
expressions, backend pipelines, and extra modifiers are rejected.

### Falco profile v1

The parser accepts exactly one rule document and these normalized fields:
`evt.type`, `evt.source`, `evt.outcome`, `target.role`, `mitre.technique`, and
`actor.name`. Conditions support parentheses, `and`, `or`, `not`, `=`, `!=`,
`contains`, and `in (...)`.

Macros, lists, exceptions, transformers, plugin fields, and other Falco grammar are
rejected.

### YARA profile

`yara-python==4.5.4` compiles the source. The manifest must name a declared rule.
External includes and module imports are rejected to keep evaluation self-contained;
each match has a one-second timeout.
