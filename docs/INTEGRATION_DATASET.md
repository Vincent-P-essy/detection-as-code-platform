# Golden incident dataset integration

## Source contract

The packaged `autonomous-payroll` telemetry is imported from the
`payroll-no-malware` golden export of `autonomous-incident-simulator`. The
provenance document records:

- source project, repository locator, and scenario identifier;
- import date and contract version;
- upstream and vendored SHA-256 for `report.json` and `telemetry.jsonl`;
- the simulator's canonical report SHA-256.

The runtime validates the vendored files. Supplying `--upstream` adds a byte-level
comparison against a sibling checkout, but this is optional and never required by
CI or an installed wheel. This avoids a fragile filesystem dependency while
preserving traceable cross-project evidence.

## Integrity identities

| Artifact | SHA-256 |
|---|---|
| Golden report bytes | `cb2719690c50b6ef099d94bf32fbccb0a3dd5e1c2128982789b074568f67b805` |
| Golden telemetry bytes | `5535218cf22b9b61249e5c7d6d31994a3da033c5b355a8488ed104351d1c3629` |
| Simulator canonical report | `62bfe9f7034703656420f794fe5f5d4fe2d5f0e59988195d6424d6c1b967318a` |

## Why the report is vendored

Replay consumes telemetry, while the report supplies traceability to the simulator
output and its canonical scenario identity. Keeping both bytes makes it possible
to prove that the input was not reconstructed manually for favorable metrics.

## Verification

```bash
detection-platform verify-dataset
detection-platform verify-dataset \
  --upstream ../autonomous-incident-simulator/datasets/golden/payroll-no-malware
```

Mutation of either vendored artifact causes validation to fail before evaluation.
