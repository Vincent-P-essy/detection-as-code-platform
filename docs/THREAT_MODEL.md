# Threat model

## Scope

This model covers local/CI validation of reviewed repository content and the local
dashboard. It does not cover an enterprise SIEM deployment because no deployment
connector exists.

## Assets

- integrity of rule sources, manifests, corpus, measurements, and audit records;
- correctness of lifecycle decisions and ATT&CK coverage claims;
- availability of the local evaluator;
- confidentiality of host paths and unrelated local files.

The bundle contains no secrets and all included artifacts are inert.

## Trust boundaries and actors

1. A contributor can propose untrusted repository changes.
2. CI validates those changes in an isolated runner.
3. A local browser can send requests to the loopback service.
4. The packaged bundle becomes trusted only after review and all gates pass.

The application is not designed to execute arbitrary tenant-supplied rules over a
public network.

## Threats and controls

| Threat | Control |
|---|---|
| Path traversal or symlink escape | Canonical path resolution constrained to bundle root |
| Dataset/rule substitution | SHA-256 verification and provenance contract |
| Ambiguous parser input | Duplicate-key rejection, strict fields/versions/types, size caps |
| Code execution through conditions | Closed parsers; no `eval`, shell, subprocess, or dynamic imports |
| YARA dependency expansion | `include` and `import` rejected; declared entrypoint and timeout |
| Network exfiltration | No outbound client in runtime source; CI AST safety gate |
| Host-path disclosure | Public manifest rendering replaces absolute paths |
| API abuse | Loopback default, exact request schema, 16 KiB cap, content-type check |
| Browser injection/clickjacking | Static rendering, CSP, no inline scripts, nosniff, frame denial |
| Report/audit tampering | Deterministic functional digest, file hashes, chained audit records |
| Unsafe container privilege | Non-root user, read-only Compose root, dropped capabilities, limits |
| Supply-chain drift | Exact dependency locks, digest-pinned image and CI actions |

## Abuse cases explicitly tested

- duplicate YAML and JSON keys;
- unknown manifest properties;
- `../` bundle paths;
- mutated telemetry after indexing;
- unsupported Sigma quantifiers;
- unknown Falco fields;
- external YARA includes;
- extra/duplicate API fields;
- tampered audit records;
- expired rules at an explicit future date.

## Residual risks

- Native parsing occurs inside the YARA dependency. A production multi-tenant
  service should isolate compilation/evaluation per job with tighter CPU/memory
  limits and a separate security profile.
- Hashes establish identity, not authorship. A production system should verify
  signed commits, attestations, and artifact signatures.
- The local API has no authentication or TLS because it binds to loopback by
  default. Do not expose it directly to an untrusted network.
- A contributor who can modify source and snapshot together still relies on human
  review to detect dishonest labels/budgets. CI checks consistency, not semantic
  truth.
- Denial-of-service analysis is bounded but not exhaustive; production ingestion
  requires queues, quotas, cancellation, and per-tenant isolation.
