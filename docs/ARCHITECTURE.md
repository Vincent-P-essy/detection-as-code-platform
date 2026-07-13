# Architecture

## Goal and boundary

The platform turns detection rules into testable software artifacts. Its trusted
input is a packaged, reviewed bundle. Its outputs are evidence and simulated
lifecycle decisions; deployment is deliberately out of scope.

```text
                         trust boundary: packaged bundle
 +-----------------------------------------------------------------------+
 | manifests --> rule sources --> compilers                              |
 |      |               |          | Sigma | Falco | YARA                |
 |      +---------------+----------+----------------------+               |
 |                                                        |               |
 | integrity index --> telemetry/artifact corpus --> replay evaluator     |
 |                                                        |               |
 |                         metrics + diagnostics + deterministic policy   |
 |                                                        |               |
 |                         reports + chained audit                         |
 +-----------------------------------+-----------------------------------+
                                     |
                       CLI / bounded API / static dashboard
```

## Components

1. **Bundle resolver** resolves relative paths and rejects absolute paths,
   `..`, and symlink escapes.
2. **Strict loaders** cap input sizes and reject malformed documents, duplicate
   YAML/JSON keys, unknown fields, and unsupported contract versions.
3. **Manifest validator** builds immutable domain objects and verifies source
   existence, engine suffix, dates, enums, tests, budgets, and SHA-256.
4. **Engine adapters** compile only documented semantics. Sigma and Falco use
   closed parsers without dynamic evaluation. YARA uses its official Python
   runtime with modules/includes disabled by policy.
5. **Corpus loader** verifies every telemetry/artifact hash before parsing. It
   separates unit fixtures from historical replay cases.
6. **Replay evaluator** runs tests, evaluates each compatible replay case, records
   per-match latency, calculates the confusion matrix, and diagnoses lifecycle
   risks.
7. **Policy engine** maps evidence to `PROMOTE`, `HOLD`, or `REJECT` in a fixed
   order. It changes no external state.
8. **Audit chain** hashes deterministic revision and lifecycle events. Each record
   commits to the preceding record.
9. **Presentation layer** exports JSON, CSV, Markdown, and a dependency-free web
   view. The API accepts only a replay date.

## Data flow and failure semantics

Validation precedes evaluation. A hash mismatch, unsupported grammar, missing test,
bad date, unknown field, or broken audit chain terminates the operation. No partial
report is promoted as valid. A legitimate rule that misses a performance budget is
represented in the report but rejected/held by policy.

The functional report view excludes measured latency and runtime metadata. This
allows policy evidence to have a reproducible SHA-256 across machines while still
retaining honest local timings in the full report.

## Lifecycle state machine

```text
draft --> validated --> canary --> production --> retired
   |          |           |
   +----------+-----------+--> quarantined
```

The requested state is metadata. The policy calculates a resulting state:

- rejection defects (`expired`, `noisy`, quality under budget, failed unit test)
  result in `REJECT` and simulated `quarantined` state;
- `silent`, `redundant`, or latency-budget defects result in `HOLD` at the current
  state;
- otherwise the rule receives `PROMOTE` to its requested state.

Redundancy compares alert-set Jaccard similarity for rules of the same case kind
with overlapping ATT&CK coverage. At `>= 0.8`, the more mature lifecycle state is
preferred, with the rule identifier as deterministic tie-breaker.

## Deployment topology

The local Python process and container expose the same interface. The container is
non-root, has a read-only root filesystem under Compose, no added capabilities,
and no writable application state. Reports requested through the dashboard are
returned to the browser; persisted exports are a CLI responsibility.

## Deliberate dependency choices

The standard library supplies HTTP, CLI, JSON, CSV, and test infrastructure.
PyYAML parses reviewed rule documents, and `yara-python` provides real YARA
semantics. Avoiding a web framework keeps the attack surface and dependency graph
small for this bounded demonstrator.
