import type { ScanSnapshot } from "../../lib/types";

export function baseSnapshot(): ScanSnapshot {
  return {
    id: "scan-test",
    schemaVersion: "2026.03",
    collectedAt: "2026-03-10T12:00:00.000Z",
    collectorVersion: "0.2.0",
    system: {
      distro: "Debian GNU/Linux 12",
      version: "12",
      kernelRelease: "6.12.0",
      kernelCommandLine: "quiet splash",
      secureBootState: "enabled",
      seccompAvailable: true
    },
    environment: {
      distroFamily: "debian",
      supportTier: "first-class",
      initSystem: "systemd",
      packageManager: "dpkg",
      virtualization: "qemu-kvm",
      advisoryCoverage: "supported",
      collectionWarnings: [],
      capabilities: []
    },
    packages: [],
    services: [],
    mounts: [],
    network: {
      hostname: "guest",
      dnsServers: [
        {
          address: "1.1.1.1",
          source: "/etc/resolv.conf",
          observedAt: "2026-03-10T12:00:00.000Z",
          trustHint: "public"
        }
      ],
      routes: [
        {
          raw: "default via 10.0.2.2 dev eth0",
          destination: "default",
          via: "10.0.2.2",
          device: "eth0",
          scope: "default",
          observedAt: "2026-03-10T12:00:00.000Z",
          collectedFrom: "ip route show"
        }
      ],
      neighbors: [],
      listeningSockets: [],
      publicListeningSockets: [],
      discoveryListeningSockets: [],
      metadataRoutePresent: false,
      defaultGatewayType: "slirp",
      bridgeLikely: false,
      multicastExposure: false
    },
    filePermissionIssues: [],
    security: {
      lsm: {
        selinuxMode: "enforcing",
        appArmorEnabled: true,
        appArmorProfilesLoaded: true
      },
      firewall: {
        backend: "nftables",
        manager: "nftables",
        rulesPresent: true,
        inspectionAvailable: true,
        defaultDenyInbound: true,
        defaultDenyOutbound: false,
        inputPolicy: "drop",
        outputPolicy: "accept",
        inferenceQuality: "exact",
        activeManagers: ["nftables"],
        rawSummary: ["table inet filter"],
        source: "nft",
        collectedFrom: "nft list ruleset",
        parser: "regex-policy"
      },
      ssh: {
        installed: false,
        configFiles: [],
        directives: []
      },
      sudoers: {
        nopasswdEntries: [],
        parsedFiles: []
      }
    },
    virtualization: {
      qemuGuestAgent: false,
      guestAgentChannels: [],
      spiceVdagent: false,
      clipboardIntegrationPossible: false,
      sharedFolderMounts: [],
      vsockEnabled: false,
      serialChannels: [],
      passthroughHints: [],
      timeSyncHints: [],
      sharedMemoryHints: [],
      rngDevicePresent: true,
      ballooningEnabled: false,
      nestedVirtExposed: false,
      ksmActive: false,
      balloonDriverPresent: false,
      balloonActiveAdjusting: false
    },
    advisoryBundle: {
      bundleId: "sample",
      generatorVersion: "fixture",
      generatedAt: "2026-03-10T00:00:00.000Z",
      expiresAt: "2026-04-10T00:00:00.000Z",
      verified: true,
      valid: true,
      stale: false,
      source: "test",
      sha256: "abc123",
      supportScope: ["debian-12", "ubuntu-24.04"],
      coverage: "supported",
      issues: []
    },
    vulnerabilities: []
  };
}
