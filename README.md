# GuestLens

Analyze your QEMU/KVM Linux systems from the inside. Discover exposed services, guest agents, firewall gaps, and trust boundary violations - all locally, no cloud required.

## Overview

GuestLens is a local-first, guest-visible security posture analyzer for Linux virtual machines running under QEMU/KVM. It is designed for developers and sysadmins who need precise evidence about a guest can actually observe from inside the VM, especially in offline or air-gapped environments.

Unlike traditional vulnerability scanners that run from the host, GuestLens inspects the VM from the inside out - revealing exactly what your virtual machine can see about itself, its exposure surfaces, and potential data leakage paths.

## Why GuestLens?

- **Guest-Visible Only**: Reports only what the VM can directly observe about itself
- **Air-Gapped Ready**: Works completely offline with local advisory bundles
- **Evidence-Backed**: Every finding includes source commands, file paths, and confidence levels
- **Repeatable**: Scan history with delta comparisons to track changes over time
- **Local-Only**: No cloud dependencies, no network required

## Features

### Security Checks

GuestLens performs comprehensive security analysis across multiple categories:

| Category | Checks |
|----------|--------|
| **Guest Hardening** | SELinux/AppArmor enforcement, firewall rules, SSH hardening, sudoers NOPASSWD |
| **Exposure Surface** | Public listening sockets, exposed services, firewall visibility |
| **Guest-Host Interface** | Shared folder mounts (virtiofs/9p), QEMU guest agent, SPICE vdagent, AF_VSOCK |
| **Discovery & Metadata** | Avahi/mDNS services, multicast listeners, cloud metadata routes |
| **File Permissions** | World-writable sensitive paths in /etc, /usr/local, /var/lib |
| **Package Advisories** | Match installed packages against offline vulnerability bundles |

### Trust Boundary Model

GuestLens categorizes findings by certainty:

- **Authoritative**: Direct evidence from guest-visible state (e.g., firewall rules, listening sockets)
- **Inferred**: Likely exposure based on guest-visible clues (e.g., guest agent present)
- **Unverifiable**: Host-only controls the guest cannot see (e.g., libvirt XML, IOMMU)

### Policy Profiles

Choose from three scanning profiles:

- **Balanced**: Default security posture for general workloads
- **High-Isolation**: Enhanced scrutiny of guest-host integration surfaces
- **Paranoid Lab**: Maximum hardening for isolated lab environments

## Architecture

GuestLens consists of three local subsystems:

1. **Collector** - Gathers guest-visible state via filesystem inspection and shell commands
2. **Analyzer** - Converts snapshots into findings, posture scores, and deltas
3. **Dashboard** - Local Next.js UI for viewing, filtering, and exporting results

### Data Flow

```
Collector reads /proc, /sys, systemctl, ss, iptables, etc.
         ↓
Snapshot stored in SQLite with schema version
         ↓
Analyzer generates findings with fingerprints
         ↓
Dashboard serves findings, history, and exports
```

### Technology Stack

- **Runtime**: Bun 1.3.x
- **Framework**: Next.js 15 (App Router)
- **UI**: React 19
- **Database**: SQLite (better-sqlite3)
- **Language**: TypeScript

## Installation

### Requirements

- Bun 1.3.x
- Node.js compatible with Next.js 15
- QEMU/KVM environment (for best results)
- Ubuntu 22.04+, Debian 12+ (first-class support)

### Setup

```bash
# Install dependencies
bun install

# Start collector and dashboard
bun run dev
```

Open `http://127.0.0.1:3000` from inside the guest VM.

### Production Build

```bash
bun run build
bun run start
```

### Collector Only

```bash
bun run collector
```

## Usage

### Running a Scan

1. Start GuestLens with `bun run dev`
2. Open the dashboard at `http://127.0.0.1:3000`
3. Click "Run guest scan" to perform analysis
4. Review findings in the Control Room

### Exporting Results

- **HTML Report**: Full formatted report for sharing
- **JSON Export**: Machine-readable format for automation

### Advisory Bundles

GuestLens supports offline vulnerability advisory bundles for package-level CVE matching.

```bash
bun run advisories:import /path/to/advisories.bundle.json
```

The bundle loader records:
- Bundle ID and generator version
- Declared support scope
- SHA256 fingerprint
- Signature verification status
- Stale or unsupported coverage warnings

## Default Paths

| Purpose | Path |
|---------|------|
| Runtime socket | `$XDG_RUNTIME_DIR/guestlens/collector.sock` |
| Fallback socket | `/tmp/guestlens-<uid>/collector.sock` |
| State directory | `$XDG_STATE_HOME/guestlens` |
| Fallback state | `~/.local/state/guestlens` |
| Database | `guestlens.db` |

## State & Backup

The state directory contains:
- Scan history
- Findings and deltas
- Suppressions
- Imported advisory bundles

Back up this directory to preserve all data.

## Security Findings Reference

### Rule IDs

| Rule ID | Description |
|---------|-------------|
| `guest.lsm.not-enforcing` | SELinux or AppArmor not in enforcing mode |
| `guest.firewall.missing` | No active firewall ruleset detected |
| `guest.firewall.not-default-deny` | Firewall lacks default-deny inbound policy |
| `guest.firewall.visibility-limited` | Firewall inspection blocked by permissions |
| `guest.ssh.weak-defaults` | SSH allows password auth, root login, or X11 forwarding |
| `guest.sudoers.nopasswd` | Passwordless sudo entries found |
| `guesthost.shared-folders.present` | virtiofs or 9p shared mounts detected |
| `guesthost.qemu-guest-agent.present` | QEMU guest agent channel accessible |
| `guesthost.spice-vdagent.present` | SPICE vdagent installed |
| `guesthost.vsock.present` | AF_VSOCK support visible |
| `guest.discovery.avahi-active` | Avahi-daemon service active |
| `guest.network.discovery-sockets` | Multicast discovery listeners bound |
| `guest.network.public-listeners` | Services listening on non-loopback addresses |
| `guesthost.network.metadata-route` | Cloud metadata route (169.254.169.254) present |
| `guest.files.world-writable-sensitive` | World-writable files in privileged paths |
| `guest.packages.advisory-match` | Installed package matches advisory |
| `guest.advisory-bundle.stale` | Advisory bundle is outdated |
| `guest.advisory-bundle.unverified` | Advisory bundle not cryptographically verified |

## Support

### First-Class Support

- Debian 12 guests
- Ubuntu 22.04+ LTS guests
- QEMU/KVM environments
- systemd-based systems

### Best-Effort Support

- RPM-based guests (RHEL, Fedora, Rocky, Alma)
- Arch Linux
- non-systemd layouts (SysVinit, OpenRC)

## Troubleshooting

**Collector socket unavailable:**
```bash
bun run collector
# or
bun run dev
```

**Firewall visibility limited:**
Run with sudo for complete firewall rule inspection:
```bash
sudo bun run collector
```

**Advisory findings limited:**
Import a production advisory bundle with Debian/Ubuntu support scope.

## Development

### Running Tests

```bash
bun test
```

### Type Checking

```bash
bun x tsc --noEmit
```

### Building

```bash
bun run build
```

## License

MIT. See [LICENSE](LICENSE).

## Related Documentation

- [Architecture](docs/ARCHITECTURE.md) - System design and data flow
- [Operations Runbook](docs/RUNBOOK.md) - Deployment and maintenance
- [Security Policy](SECURITY.md) - Security reporting guidelines
