# Contributing

Changes should preserve the evidence-first contract and the explicit distinction
between simulation and deployment.

1. Create or update a manifest and its pinned local source.
2. Add at least one positive and one negative inert fixture.
3. Keep the grammar inside the documented engine profile.
4. Increment the revision, update dates, retain a finite expiry, and justify
   performance budgets.
5. Run `make test` and `make quality`.
6. Include changed metrics and limitations in the review description.

Do not add live credentials, production telemetry, active malware, shell execution,
outbound runtime clients, hidden deployment effects, or unsupported syntax that is
silently approximated.
