# Limitations and honest claims

## What this project proves

- versioned, reviewable detection metadata with ownership and expiry;
- executable positive/negative tests for three rule formats;
- integrity-checked historical replay with measured functional metrics;
- deterministic noise, silence, redundancy, expiration, and lifecycle policies;
- self-contained cross-project golden-data integration;
- reproducible machine/human reports and tamper-evident audit evidence;
- CLI, local API, dashboard, hardened container, and automated quality gates.

## What it does not prove

- **No real deployment.** Lifecycle decisions never write to a SIEM, Falco sensor,
  EDR, or Kubernetes cluster. Canary percentages are policy metadata only.
- **No full Sigma/Falco compatibility.** Both use documented executable subsets.
  Unsupported syntax is rejected rather than approximated.
- **No representative detection benchmark.** The corpus is small, controlled, and
  synthetic. Precision/recall values must not be generalized to enterprise logs.
- **No global event labels.** Ground truth is rule-scoped and authored with the
  rules; independent analyst adjudication is absent.
- **No production performance claim.** Latency is a single-process per-case
  microbenchmark excluding ingestion and compilation. Throughput and scale are
  unmeasured.
- **No public-service security claim.** The server has no authentication, TLS,
  tenancy, queue, database, or distributed state and should stay on loopback.
- **No cryptographic signature.** SHA-256 and a hash chain detect modification
  relative to trusted metadata; they do not establish signer identity.
- **No ATT&CK completeness.** Coverage represents techniques declared by the seven
  demonstrator rules, not an environment-wide coverage assessment.

## Sensible production extensions

Use official Sigma conversion/backends and Falco validation, isolate native rule
execution, store signed revisions in an append-only service, ingest statistically
meaningful and independently labelled data, add tenant authentication/authorization,
stage rules against a real canary telemetry stream, require reviewer approvals,
and implement rollback-aware deployment connectors with external audit evidence.
