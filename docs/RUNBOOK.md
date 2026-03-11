# Operations Runbook

## First run

1. Install dependencies with `bun install`.
2. Start the collector and dashboard with `bun run dev`, or build and run with `bun run build` then `bun run start`.
3. Open `http://127.0.0.1:3000` from inside the guest.
4. Import an offline advisory bundle if you have one:

```bash
bun run advisories:import /path/to/advisories.bundle.json
```

5. Run the first scan from the dashboard.
6. Export an HTML report and JSON artifact for recordkeeping.

## State and backup

- Runtime socket: under `$XDG_RUNTIME_DIR/guestlens` or `/tmp/guestlens-<uid>`
- Persistent state: under `$XDG_STATE_HOME/guestlens` or `~/.local/state/guestlens`

Backup the full state directory to preserve:

- scan history
- suppressions
- imported advisory bundle

## Restore

1. Stop the collector and dashboard.
2. Restore the state directory contents.
3. Restart the services.

## Troubleshooting

- If the dashboard reports that the collector socket is unavailable, start `bun run collector` or `bun run dev`.
- If firewall coverage is permission-limited, rerun with sufficient guest privileges for ruleset inspection.
- If advisory findings show limited or unsupported coverage, import a bundle that declares Debian/Ubuntu support scope.
