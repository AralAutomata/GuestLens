import { describe, expect, test } from "bun:test";

import { analyzeSnapshot } from "../lib/security/analyzer";
import type { ScanSnapshot } from "../lib/types";

function baseSnapshot(): ScanSnapshot {
  return {
    id: "scan-test",
    collectedAt: "2026-03-10T12:00:00.000Z",
    collectorVersion: "0.1.0",
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
      dnsServers: ["1.1.1.1"],
      routes: ["default via 10.0.2.2 dev eth0"],
      neighbors: [],
      listeningSockets: [],
      publicListeningSockets: [],
      metadataRoutePresent: false
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
        rulesPresent: true,
        defaultDenyInbound: true,
        defaultDenyOutbound: false,
        rawSummary: ["table inet filter"]
      },
      ssh: {
        installed: false
      },
      sudoers: {
        nopasswdEntries: []
      }
    },
    virtualization: {
      qemuGuestAgent: false,
      spiceVdagent: false,
      sharedFolderMounts: [],
      vsockEnabled: false,
      serialChannels: [],
      passthroughHints: [],
      timeSyncHints: [],
      rngDevicePresent: true,
      ballooningEnabled: false
    },
    advisoryBundle: {
      bundleId: "sample",
      generatedAt: "2026-03-10T00:00:00.000Z",
      expiresAt: "2026-04-10T00:00:00.000Z",
      verified: false,
      stale: false,
      source: "test",
      sha256: "abc123"
    },
    vulnerabilities: []
  };
}

describe("analyzeSnapshot", () => {
  test("keeps a hardened baseline free of high severity guest findings", () => {
    const result = analyzeSnapshot(baseSnapshot());

    expect(result.findings.some((finding) => finding.severity === "high" && finding.boundary === "guest")).toBe(false);
    expect(result.findings.some((finding) => finding.confidence === "unverifiable")).toBe(true);
    expect(result.posture.overallScore).toBeGreaterThan(70);
  });

  test("flags shared folders as guest-host leakage risk", () => {
    const snapshot = baseSnapshot();
    snapshot.virtualization.sharedFolderMounts = [
      {
        mountPoint: "/mnt/hostshare",
        fsType: "virtiofs",
        source: "hostshare",
        options: ["rw"]
      }
    ];

    const result = analyzeSnapshot(snapshot);
    const finding = result.findings.find((item) => item.id === "shared-folder-mounts-detected");

    expect(finding).toBeDefined();
    expect(finding?.boundary).toBe("guest-host interface");
    expect(finding?.remediation.some((item) => item.id === "unmount-shared-folders")).toBe(true);
  });

  test("flags SPICE and guest-agent integrations", () => {
    const snapshot = baseSnapshot();
    snapshot.virtualization.spiceVdagent = true;
    snapshot.virtualization.qemuGuestAgent = true;

    const result = analyzeSnapshot(snapshot);

    expect(result.findings.find((item) => item.id === "spice-vdagent-present")).toBeDefined();
    expect(result.findings.find((item) => item.id === "qemu-guest-agent-present")).toBeDefined();
  });

  test("flags weak SSH and public listeners", () => {
    const snapshot = baseSnapshot();
    snapshot.security.ssh = {
      installed: true,
      passwordAuthentication: "yes",
      permitRootLogin: "yes",
      x11Forwarding: "yes",
      pubkeyAuthentication: "yes"
    };
    snapshot.network.publicListeningSockets = [
      {
        protocol: "tcp",
        localAddress: "0.0.0.0:22",
        raw: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
      }
    ];

    const result = analyzeSnapshot(snapshot);

    expect(result.findings.find((item) => item.id === "ssh-configuration-weak")).toBeDefined();
    expect(result.findings.find((item) => item.id === "public-listeners-present")).toBeDefined();
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
        summary: "Example issue",
        severity: "high",
        cves: ["CVE-2025-DEMO-0001"],
        source: "bundle"
      }
    ];

    const result = analyzeSnapshot(snapshot);
    const finding = result.findings.find((item) => item.id === "advisory-openssh-server");

    expect(finding?.confidence).toBe("inferred");
    expect(result.findings.find((item) => item.id === "advisory-bundle-stale")).toBeDefined();
  });
});

