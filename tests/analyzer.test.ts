import { describe, expect, test } from "bun:test";

import { analyzeSnapshot } from "../lib/security/analyzer";
import { baseSnapshot } from "./fixtures/snapshots";

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
      configFiles: ["/etc/ssh/sshd_config"],
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
    snapshot.network.discoveryListeningSockets = [];

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
