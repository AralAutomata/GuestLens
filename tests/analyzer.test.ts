import { describe, expect, test } from "bun:test";

import { analyzeSnapshot } from "../lib/security/analyzer";
import type { ScanSnapshot } from "../lib/types";

function baseSnapshot(): ScanSnapshot {
  return {
    id: "scan-test",
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
        directives: []
      },
      sudoers: {
        nopasswdEntries: []
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
      ballooningEnabled: false
    },
    advisoryBundle: {
      bundleId: "sample",
      generatedAt: "2026-03-10T00:00:00.000Z",
      expiresAt: "2026-04-10T00:00:00.000Z",
      verified: true,
      stale: false,
      source: "test",
      sha256: "abc123"
    },
    vulnerabilities: []
  };
}

describe("analyzeSnapshot", () => {
  test("keeps a hardened baseline free of high severity guest findings", () => {
    const result = analyzeSnapshot(baseSnapshot(), "balanced");

    expect(result.findings.some((finding) => finding.severity === "high" && finding.boundary === "guest")).toBe(false);
    expect(result.findings.some((finding) => finding.confidence === "unverifiable")).toBe(true);
    expect(result.posture.overallScore).toBeGreaterThan(70);
    expect(result.groups.length).toBeGreaterThan(0);
  });

  test("flags shared folders as guest-host leakage risk", () => {
    const snapshot = baseSnapshot();
    snapshot.virtualization.sharedFolderMounts = [
      {
        mountPoint: "/mnt/hostshare",
        fsType: "virtiofs",
        source: "hostshare",
        options: ["rw"],
        observedAt: snapshot.collectedAt,
        collectedFrom: "/proc/mounts"
      }
    ];

    const result = analyzeSnapshot(snapshot, "high-isolation");
    const finding = result.findings.find((item) => item.id === "shared-folder-mounts-detected");

    expect(finding).toBeDefined();
    expect(finding?.boundary).toBe("guest-host interface");
    expect(finding?.remediation.some((item) => item.id === "unmount-shared-folders")).toBe(true);
    expect(finding?.profile).toBe("high-isolation");
  });

  test("flags SPICE and guest-agent integrations", () => {
    const snapshot = baseSnapshot();
    snapshot.virtualization.spiceVdagent = true;
    snapshot.virtualization.qemuGuestAgent = true;
    snapshot.virtualization.guestAgentChannels = ["/dev/virtio-ports/org.qemu.guest_agent.0"];

    const result = analyzeSnapshot(snapshot, "paranoid-lab");

    expect(result.findings.find((item) => item.id === "spice-vdagent-present")).toBeDefined();
    expect(result.findings.find((item) => item.id === "qemu-guest-agent-present")).toBeDefined();
  });

  test("flags weak SSH and public listeners with grouped evidence", () => {
    const snapshot = baseSnapshot();
    snapshot.security.ssh = {
      installed: true,
      permitRootLogin: "yes",
      passwordAuthentication: "yes",
      x11Forwarding: "yes",
      pubkeyAuthentication: "yes",
      directives: [
        {
          key: "PasswordAuthentication",
          value: "yes",
          source: "/etc/ssh/sshd_config",
          observedAt: snapshot.collectedAt,
          collectedFrom: "ssh-config"
        }
      ]
    };
    snapshot.network.publicListeningSockets = [
      {
        protocol: "tcp",
        family: "ipv4",
        state: "LISTEN",
        host: "0.0.0.0",
        port: 22,
        localAddress: "0.0.0.0:22",
        process: "sshd",
        pid: 999,
        bindScope: "wildcard",
        reachability: "wildcard",
        raw: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=999,fd=3))",
        collectedFrom: "ss -H -lntup",
        parser: "ss",
        observedAt: snapshot.collectedAt
      }
    ];
    snapshot.network.listeningSockets = snapshot.network.publicListeningSockets;

    const result = analyzeSnapshot(snapshot, "balanced");

    expect(result.findings.find((item) => item.id === "ssh-configuration-weak")).toBeDefined();
    expect(result.findings.find((item) => item.id === "public-listeners-present")).toBeDefined();
    expect(result.groups.find((group) => group.id === "remote-access")).toBeDefined();
  });

  test("downgrades advisory confidence when bundle is stale", () => {
    const snapshot = baseSnapshot();
    snapshot.advisoryBundle = {
      ...snapshot.advisoryBundle!,
      stale: true
    };
    snapshot.vulnerabilities = [
      {
        packageName: "openssh-server",
        installedVersion: "9.2p1",
        summary: "Example issue",
        severity: "high",
        cves: ["CVE-2025-DEMO-0001"],
        source: "bundle"
      }
    ];

    const result = analyzeSnapshot(snapshot, "balanced");
    const finding = result.findings.find((item) => item.id === "advisory-openssh-server");

    expect(finding?.confidence).toBe("inferred");
    expect(result.findings.find((item) => item.id === "advisory-bundle-stale")).toBeDefined();
  });
});
