# Architecture

GuestLens has three local subsystems:

- `collector`: gathers guest-visible state and serves scan requests over a Unix socket
- `analyzer`: converts snapshots into findings, groups, posture scores, and deltas
- `dashboard`: local Next.js UI and API layer bound to `127.0.0.1`

## Data flow

1. The collector reads local files and commands from inside the guest.
2. A scan snapshot is stored with a schema version and environment metadata.
3. The analyzer emits stable rule ids, fingerprints, remediation guidance, and posture summaries.
4. The database stores scan history, findings, deltas, and suppressions locally in SQLite.
5. The dashboard loads posture, findings, history, diff, and suppression state through local API routes.

## Trust boundaries

- The guest can directly certify only guest-visible state.
- Cross-boundary statements must remain inferred unless there is direct evidence.
- Host-side controls are tracked as unverifiable, not as proven-safe.

## Release constraints

- single-host only
- no cloud dependency
- source-only distribution
- manual advisory import only
