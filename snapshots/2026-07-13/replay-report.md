# Detection replay report

- Assessment date: `2026-07-13`
- Functional SHA-256: `ea9c4d9916b85d9c27796f6ac96992471d7a655ad2e49abf496957bfb44210cc`
- Rules: `7`
- Replay cases: `22`
- Unit-test pass rate: `92.9%`
- Decisions: `4 promote / 2 hold / 1 reject`

## Rule quality

| Rule | Engine | Decision | Precision | Recall | FPR | Alerts | Diagnostics |
|---|---|---|---:|---:|---:|---:|---|
| `falco.payroll-remote-login` | falco | PROMOTE | 1.000 | 1.000 | 0.000 | 1 | healthy |
| `sigma.broad-authentication-candidate` | sigma | REJECT | 0.333 | 1.000 | 0.105 | 3 | noisy, under_precision, unit_test_failure |
| `sigma.identity-session-anomaly` | sigma | PROMOTE | 1.000 | 1.000 | 0.000 | 1 | healthy |
| `sigma.log-deletion-canary` | sigma | HOLD | n/a | n/a | 0.000 | 0 | silent |
| `sigma.payroll-sensitive-read-shadow` | sigma | HOLD | 1.000 | 1.000 | 0.000 | 1 | redundant |
| `sigma.payroll-sensitive-read` | sigma | PROMOTE | 1.000 | 1.000 | 0.000 | 1 | healthy |
| `yara.simulated-payroll-export` | yara | PROMOTE | 1.000 | 1.000 | 0.000 | 1 | healthy |

## Diagnostics

- Silent: `sigma.log-deletion-canary`
- Noisy: `sigma.broad-authentication-candidate`
- Redundant pairs: `1`
- Expired: `none`

Promotion is simulated. This report does not deploy a rule to a SIEM or runtime sensor.
