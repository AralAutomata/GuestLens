import { describe, expect, test } from "bun:test";

import { analyzeSnapshot } from "../lib/security/analyzer";
import type { PolicyProfile } from "../lib/types";
import { baseSnapshot } from "./fixtures/snapshots";

const DANGEROUS_PATTERNS = [
  /\bdd\s+if=/i,
  /\bmkfs\b/i,
  /\bfdisk\b/i,
  /\brm\s+-rf\s+\//,
  /\bformat\s+[A-Z]:/i,
  /\bshred\b/i,
  /\bwipefs\b/i,
  /\bsystemctl\s+(disable|mask)\s+(systemd-journald|dbus)/i,
  /\bkill\s+-9\s+1\b/,
  /\becho\b.*>\s*\/dev\/sd/i
];

const PROFILES: PolicyProfile[] = ["balanced", "high-isolation", "paranoid-lab"];

describe("hardware protection invariant", () => {
  for (const profile of PROFILES) {
    test(`no remediation commands contain destructive patterns (${profile})`, () => {
      const snapshot = baseSnapshot();
      // Weaken the snapshot to trigger more findings and remediations
      snapshot.security.lsm = { selinuxMode: "disabled", appArmorEnabled: false, appArmorProfilesLoaded: false };
      snapshot.security.firewall.rulesPresent = false;
      snapshot.security.firewall.defaultDenyInbound = false;
      snapshot.security.ssh = {
        installed: true,
        configFiles: ["/etc/ssh/sshd_config"],
        permitRootLogin: "yes",
        passwordAuthentication: "yes",
        x11Forwarding: "yes",
        pubkeyAuthentication: "yes",
        directives: []
      };
      snapshot.security.sudoers.nopasswdEntries = ["user ALL=(ALL) NOPASSWD: ALL"];
      snapshot.virtualization.sharedFolderMounts = [
        { mountPoint: "/mnt/share", fsType: "virtiofs", source: "share", options: ["rw"], observedAt: snapshot.collectedAt, collectedFrom: "/proc/mounts" }
      ];
      snapshot.virtualization.qemuGuestAgent = true;
      snapshot.virtualization.guestAgentChannels = ["/dev/virtio-ports/org.qemu.guest_agent.0"];
      snapshot.virtualization.spiceVdagent = true;
      snapshot.virtualization.vsockEnabled = true;
      snapshot.network.publicListeningSockets = [
        {
          protocol: "tcp", family: "ipv4", state: "LISTEN", host: "0.0.0.0", port: 80,
          localAddress: "0.0.0.0:80", bindScope: "wildcard", reachability: "wildcard",
          raw: "tcp LISTEN 0 128 0.0.0.0:80", collectedFrom: "ss -H -lntup", parser: "ss",
          observedAt: snapshot.collectedAt
        }
      ];
      snapshot.network.bridgeLikely = true;
      snapshot.network.metadataRoutePresent = true;
      snapshot.network.routes.push({
        raw: "169.254.169.254 via 10.0.2.2 dev eth0",
        destination: "169.254.169.254",
        via: "10.0.2.2",
        device: "eth0",
        scope: "other",
        observedAt: snapshot.collectedAt,
        collectedFrom: "ip route show"
      });
      snapshot.filePermissionIssues = [
        { path: "/etc/shadow", mode: "0666", reason: "world-writable", observedAt: snapshot.collectedAt, collectedFrom: "stat" }
      ];
      snapshot.services = [
        { name: "avahi-daemon.service", enabled: true, active: true, observedAt: snapshot.collectedAt, collectedFrom: "systemctl" }
      ];
      snapshot.network.discoveryListeningSockets = [
        {
          protocol: "udp", family: "ipv4", host: "224.0.0.251", port: 5353,
          localAddress: "224.0.0.251:5353", bindScope: "specific-interface", reachability: "lan-or-host",
          raw: "udp 224.0.0.251:5353", collectedFrom: "ss -H -lntup", parser: "ss",
          observedAt: snapshot.collectedAt
        }
      ];
      snapshot.vulnerabilities = [
        { packageName: "openssl", summary: "CVE example", severity: "high", cves: ["CVE-2025-0001"], source: "bundle" }
      ];

      const result = analyzeSnapshot(snapshot, profile);

      for (const finding of result.findings) {
        for (const action of finding.remediation) {
          for (const command of action.commands) {
            for (const pattern of DANGEROUS_PATTERNS) {
              expect(pattern.test(command)).toBe(false);
            }
          }
        }
      }
    });

    test(`boot/kernel/firmware remediations are never safeForAutomationLater (${profile})`, () => {
      const snapshot = baseSnapshot();
      snapshot.security.lsm = { selinuxMode: "disabled", appArmorEnabled: false, appArmorProfilesLoaded: false };

      const result = analyzeSnapshot(snapshot, profile);
      const bootRelated = result.findings.filter((f) =>
        f.remediation.some((r) => /boot|kernel|firmware|selinux|apparmor|lsm/i.test(r.description))
      );

      for (const finding of bootRelated) {
        for (const action of finding.remediation) {
          if (/boot|kernel|firmware|selinux|apparmor/i.test(action.description)) {
            expect(action.safeForAutomationLater).toBe(false);
          }
        }
      }
    });

    test(`no remediation with mode "command" targets irreversible operations (${profile})`, () => {
      const snapshot = baseSnapshot();
      snapshot.security.firewall.rulesPresent = false;
      snapshot.security.firewall.defaultDenyInbound = false;

      const result = analyzeSnapshot(snapshot, profile);
      const commandActions = result.findings.flatMap((f) => f.remediation.filter((r) => r.mode === "command"));

      for (const action of commandActions) {
        for (const command of action.commands) {
          for (const pattern of DANGEROUS_PATTERNS) {
            expect(pattern.test(command)).toBe(false);
          }
        }
      }
    });
  }
});
