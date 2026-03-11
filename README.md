# HostGuard Linux

HostGuard Linux is a local-first, guest-visible security posture analyzer for Linux virtual machines running under QEMU/KVM. It is designed for developers and sysadmins who need precise evidence about what a guest can actually observe from inside the VM, especially in offline or air-gapped environments.

## Product contract

HostGuard Linux is intentionally strict about trust boundaries:

- `Authoritative`: guest-visible state such as services, sockets, packages, mounts, firewall state, SSH configuration, sudoers policy, and local devices.
- `Inferred`: likely exposure paths derived from guest-visible clues such as shared folders, guest agents, discovery daemons, network reachability, and advisory coverage limits.
- `Unverifiable`: host-only controls such as libvirt XML, hypervisor launch flags, host firewalling, sVirt labels, storage handling, and escape resistance.

Out of scope in this phase:

- host-side certification
- fleet management
- cloud services
- remote auth or RBAC
- automated remediation execution

## Operating model

- Local collector service over a Unix domain socket
- Local Next.js dashboard bound to `127.0.0.1`
- Source-only distribution from a public GitHub repo
- Strictly air-gapped advisory workflow via manual bundle import

Default paths:

- Runtime socket: `$XDG_RUNTIME_DIR/hostguard-linux/collector.sock`
- Runtime fallback: `/tmp/hostguard-linux-<uid>/collector.sock`
- State dir: `$XDG_STATE_HOME/hostguard-linux`
- State fallback: `~/.local/state/hostguard-linux`
- SQLite DB: `hostguard-linux.db`

## Support statement

First-class support in this phase:

- Debian 12 guests
- Ubuntu LTS guests
- QEMU/KVM environments managed locally

Best-effort support:

- RPM-based guests
- Arch-based guests
- non-systemd layouts

## Key capabilities

- repeatable guest scans with stored history and deltas
- evidence-backed findings with fingerprints and suppression support
- local dashboard for filtering, comparison, and operator review
- standalone HTML report export and versioned JSON export
- offline advisory bundle validation and coverage reporting

## Local development

Requirements:

- Bun 1.3.x
- Node.js runtime compatible with Next.js 15

Install dependencies:

```bash
bun install
```

Start collector and dashboard together:

```bash
bun run dev
```

Open locally from inside the guest:

```text
http://127.0.0.1:3000
```

Production-style startup:

```bash
bun run build
bun run start
```

Collector-only:

```bash
bun run collector
```

## Advisory bundles

HostGuard Linux ships with a bundled sample advisory bundle for offline development. Replace it before relying on package findings.

Import a bundle:

```bash
bun run advisories:import /path/to/advisories.bundle.json
```

The bundle loader records:

- bundle id
- generator version
- declared support scope
- SHA256 fingerprint
- signature verification result when trusted keys are configured
- stale or unsupported coverage warnings

## Testing

```bash
bun test
bun x tsc --noEmit
bun run build
```

## Runbooks and project docs

- [Architecture](docs/ARCHITECTURE.md)
- [Operations Runbook](docs/RUNBOOK.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
