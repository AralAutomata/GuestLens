# HostGuard Linux

HostGuard Linux is a guest-resident hardening and isolation analyzer for Linux virtual machines running under QEMU/KVM and typically managed with virt-manager. It is intentionally strict about what it can know from inside the guest:

- `Authoritative`: guest state the VM can directly observe.
- `Inferred`: likely host-guest exposure derived from guest-visible artifacts.
- `Unverifiable`: host, libvirt, and hypervisor controls that cannot be proven from inside the VM.

## Architecture

- `collector`: a local inventory service that reads guest-visible state and listens on a Unix domain socket.
- `analyzer`: converts raw guest state into posture scores, findings, and guided remediation actions.
- `remediation-helper`: executes an allowlisted subset of explicit actions when the process has root privileges.
- `web-ui`: Next.js dashboard bound to `127.0.0.1` only.

The collector socket lives under the guest runtime directory:

- default socket: `$XDG_RUNTIME_DIR/hostguard/collector.sock`
- fallback socket: `/tmp/hostguard-<uid>/collector.sock`

The application state lives under:

- default state dir: `$XDG_STATE_HOME/hostguard`
- fallback state dir: `~/.local/state/hostguard`

## What the guest can analyze well

- guest firewalling, LSM state, SSH posture, sudoers, mounts, file permissions, listening sockets, routes, DNS, systemd services, and installed packages
- guest-visible virtualization surfaces such as `qemu-guest-agent`, `spice-vdagent`, `virtiofs`, `9p`, serial channels, `vsock`, RNG devices, and ballooning drivers
- obvious leakage and accessibility clues, including public listeners, discovery daemons, shared folders, and metadata endpoint routes

## What the guest cannot certify

- libvirt XML and QEMU launch flags
- host bridge, tap, or firewall policy
- host SELinux/AppArmor/sVirt labels
- host storage permissions and snapshot handling
- host DMA/IOMMU posture
- resistance to VM escape

## Local development

1. Install dependencies:

```bash
bun install
```

2. Start the collector and the UI together:

```bash
bun run dev
```

3. Open the dashboard from inside the guest only:

```text
http://127.0.0.1:3000
```

For production-style startup:

```bash
bun run build
bun run start
```

## Advisory bundles

HostGuard ships with a bundled sample advisory bundle for offline development. Replace it with a newer offline bundle before relying on package findings.

Import a newer bundle:

```bash
bun run advisories:import /path/to/advisories.bundle.json
```

The bundle loader computes a SHA256 fingerprint and can verify embedded Ed25519 signatures when trusted keys are configured in `lib/security/advisories.ts`.

## Remediation model

- Remediation is explicit and operator-invoked.
- No background enforcement exists in this version.
- Command execution requires root privileges and only covers an allowlisted subset of actions:
  - disabling `qemu-guest-agent`
  - disabling `spice-vdagent`
  - disabling `avahi-daemon`
  - unmounting `virtiofs` and `9p` shared folders
  - enabling a guest firewall where a supported backend is present

## Tests

```bash
bun test
```

The test suite covers hardened baselines, shared folders, SPICE and guest-agent integrations, weak SSH posture, public listeners, and stale advisory bundle handling.
