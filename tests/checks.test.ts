import { describe, expect, test } from "bun:test";

import { runChecks } from "../lib/security/checks";
import type { ScanSnapshot } from "../lib/types";
import { baseSnapshot } from "./fixtures/snapshots";

function findByRule(snapshot: ScanSnapshot, ruleId: string) {
  const findings = runChecks(snapshot, "balanced");
  return findings.find((f) => f.ruleId === ruleId);
}

describe("checks — all 22 rules", () => {
  // 1. guest.lsm.not-enforcing
  describe("guest.lsm.not-enforcing", () => {
    test("does not fire when SELinux is enforcing", () => {
      const s = baseSnapshot();
      expect(findByRule(s, "guest.lsm.not-enforcing")).toBeUndefined();
    });

    test("does not fire when AppArmor is enabled (even if SELinux disabled)", () => {
      const s = baseSnapshot();
      s.security.lsm.selinuxMode = "disabled";
      s.security.lsm.appArmorEnabled = true;
      expect(findByRule(s, "guest.lsm.not-enforcing")).toBeUndefined();
    });

    test("fires when SELinux is permissive and AppArmor is off", () => {
      const s = baseSnapshot();
      s.security.lsm.selinuxMode = "permissive";
      s.security.lsm.appArmorEnabled = false;
      const f = findByRule(s, "guest.lsm.not-enforcing");
      expect(f).toBeDefined();
      expect(f!.boundary).toBe("guest");
      expect(f!.severity).toBe("high");
    });
  });

  // 1b. guest.lsm.disabled (new — from bug fix split)
  describe("guest.lsm.disabled", () => {
    test("fires when SELinux is disabled and AppArmor is off", () => {
      const s = baseSnapshot();
      s.security.lsm.selinuxMode = "disabled";
      s.security.lsm.appArmorEnabled = false;
      const f = findByRule(s, "guest.lsm.disabled");
      expect(f).toBeDefined();
      expect(f!.boundary).toBe("guest");
    });

    test("does not fire when SELinux is permissive", () => {
      const s = baseSnapshot();
      s.security.lsm.selinuxMode = "permissive";
      s.security.lsm.appArmorEnabled = false;
      expect(findByRule(s, "guest.lsm.disabled")).toBeUndefined();
    });
  });

  // 2. guest.firewall.visibility-limited
  describe("guest.firewall.visibility-limited", () => {
    test("fires when inspection is unavailable", () => {
      const s = baseSnapshot();
      s.security.firewall.inspectionAvailable = false;
      const f = findByRule(s, "guest.firewall.visibility-limited");
      expect(f).toBeDefined();
      expect(f!.confidence).toBe("inferred");
    });

    test("does not fire when inspection is available", () => {
      expect(findByRule(baseSnapshot(), "guest.firewall.visibility-limited")).toBeUndefined();
    });
  });

  // 3. guest.firewall.missing
  describe("guest.firewall.missing", () => {
    test("fires when no rules present", () => {
      const s = baseSnapshot();
      s.security.firewall.rulesPresent = false;
      const f = findByRule(s, "guest.firewall.missing");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("high");
      expect(f!.confidence).toBe("authoritative");
    });

    test("does not fire when rules are present", () => {
      expect(findByRule(baseSnapshot(), "guest.firewall.missing")).toBeUndefined();
    });
  });

  // 4. guest.firewall.not-default-deny
  describe("guest.firewall.not-default-deny", () => {
    test("fires when rules present but no default deny", () => {
      const s = baseSnapshot();
      s.security.firewall.defaultDenyInbound = false;
      const f = findByRule(s, "guest.firewall.not-default-deny");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("medium");
    });

    test("does not fire when default deny is set", () => {
      expect(findByRule(baseSnapshot(), "guest.firewall.not-default-deny")).toBeUndefined();
    });
  });

  // 5. guest.firewall.heuristic-visibility
  describe("guest.firewall.heuristic-visibility", () => {
    test("fires when inference quality is heuristic", () => {
      const s = baseSnapshot();
      s.security.firewall.inferenceQuality = "heuristic";
      const f = findByRule(s, "guest.firewall.heuristic-visibility");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("low");
    });

    test("does not fire when inference quality is exact", () => {
      expect(findByRule(baseSnapshot(), "guest.firewall.heuristic-visibility")).toBeUndefined();
    });
  });

  // 6. guest.ssh.weak-defaults
  describe("guest.ssh.weak-defaults", () => {
    test("fires when SSH has weak settings", () => {
      const s = baseSnapshot();
      s.security.ssh = {
        installed: true,
        configFiles: ["/etc/ssh/sshd_config"],
        permitRootLogin: "yes",
        passwordAuthentication: "yes",
        x11Forwarding: "no",
        directives: []
      };
      const f = findByRule(s, "guest.ssh.weak-defaults");
      expect(f).toBeDefined();
      expect(f!.evidence.length).toBeGreaterThan(0);
    });

    test("does not fire when SSH is not installed", () => {
      expect(findByRule(baseSnapshot(), "guest.ssh.weak-defaults")).toBeUndefined();
    });

    test("does not fire when all SSH settings are hardened", () => {
      const s = baseSnapshot();
      s.security.ssh = {
        installed: true,
        configFiles: ["/etc/ssh/sshd_config"],
        permitRootLogin: "no",
        passwordAuthentication: "no",
        x11Forwarding: "no",
        directives: []
      };
      expect(findByRule(s, "guest.ssh.weak-defaults")).toBeUndefined();
    });
  });

  // 7. guest.sudoers.nopasswd
  describe("guest.sudoers.nopasswd", () => {
    test("fires when NOPASSWD entries exist", () => {
      const s = baseSnapshot();
      s.security.sudoers.nopasswdEntries = ["user ALL=(ALL) NOPASSWD: ALL"];
      const f = findByRule(s, "guest.sudoers.nopasswd");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("medium");
    });

    test("does not fire when no NOPASSWD entries", () => {
      expect(findByRule(baseSnapshot(), "guest.sudoers.nopasswd")).toBeUndefined();
    });
  });

  // 8. guesthost.shared-folders.present
  describe("guesthost.shared-folders.present", () => {
    test("fires when shared mounts exist", () => {
      const s = baseSnapshot();
      s.virtualization.sharedFolderMounts = [
        { mountPoint: "/mnt/share", fsType: "virtiofs", source: "share", options: ["rw"], observedAt: s.collectedAt, collectedFrom: "/proc/mounts" }
      ];
      const f = findByRule(s, "guesthost.shared-folders.present");
      expect(f).toBeDefined();
      expect(f!.boundary).toBe("guest-host interface");
    });

    test("does not fire when no shared mounts", () => {
      expect(findByRule(baseSnapshot(), "guesthost.shared-folders.present")).toBeUndefined();
    });
  });

  // 9. guesthost.qemu-guest-agent.present
  describe("guesthost.qemu-guest-agent.present", () => {
    test("fires when guest agent is present", () => {
      const s = baseSnapshot();
      s.virtualization.qemuGuestAgent = true;
      s.virtualization.guestAgentChannels = ["/dev/virtio-ports/org.qemu.guest_agent.0"];
      const f = findByRule(s, "guesthost.qemu-guest-agent.present");
      expect(f).toBeDefined();
    });

    test("does not fire when guest agent is absent", () => {
      expect(findByRule(baseSnapshot(), "guesthost.qemu-guest-agent.present")).toBeUndefined();
    });
  });

  // 10. guesthost.spice-vdagent.present
  describe("guesthost.spice-vdagent.present", () => {
    test("fires when SPICE is active", () => {
      const s = baseSnapshot();
      s.virtualization.spiceVdagent = true;
      const f = findByRule(s, "guesthost.spice-vdagent.present");
      expect(f).toBeDefined();
      expect(f!.boundary).toBe("guest-host interface");
    });

    test("does not fire when SPICE is inactive", () => {
      expect(findByRule(baseSnapshot(), "guesthost.spice-vdagent.present")).toBeUndefined();
    });
  });

  // 11. guesthost.vsock.present
  describe("guesthost.vsock.present", () => {
    test("fires when vsock is enabled", () => {
      const s = baseSnapshot();
      s.virtualization.vsockEnabled = true;
      const f = findByRule(s, "guesthost.vsock.present");
      expect(f).toBeDefined();
    });

    test("does not fire when vsock is disabled", () => {
      expect(findByRule(baseSnapshot(), "guesthost.vsock.present")).toBeUndefined();
    });

    test("has authoritative confidence and guest-host interface boundary", () => {
      const s = baseSnapshot();
      s.virtualization.vsockEnabled = true;
      const f = findByRule(s, "guesthost.vsock.present");
      expect(f).toBeDefined();
      expect(f!.confidence).toBe("authoritative");
      expect(f!.boundary).toBe("guest-host interface");
    });
  });

  // 12. guest.discovery.avahi-active
  describe("guest.discovery.avahi-active", () => {
    test("fires when avahi-daemon is active", () => {
      const s = baseSnapshot();
      s.services = [
        { name: "avahi-daemon.service", enabled: true, active: true, observedAt: s.collectedAt, collectedFrom: "systemctl" }
      ];
      const f = findByRule(s, "guest.discovery.avahi-active");
      expect(f).toBeDefined();
    });

    test("does not fire when avahi-daemon is absent", () => {
      expect(findByRule(baseSnapshot(), "guest.discovery.avahi-active")).toBeUndefined();
    });
  });

  // 13. guest.network.discovery-sockets
  describe("guest.network.discovery-sockets", () => {
    test("fires when discovery sockets exist", () => {
      const s = baseSnapshot();
      s.network.discoveryListeningSockets = [
        {
          protocol: "udp", family: "ipv4", host: "224.0.0.251", port: 5353,
          localAddress: "224.0.0.251:5353", bindScope: "specific-interface", reachability: "lan-or-host",
          raw: "udp 224.0.0.251:5353", collectedFrom: "ss -H -lntup", parser: "ss",
          observedAt: s.collectedAt
        }
      ];
      const f = findByRule(s, "guest.network.discovery-sockets");
      expect(f).toBeDefined();
    });

    test("does not fire when no discovery sockets", () => {
      expect(findByRule(baseSnapshot(), "guest.network.discovery-sockets")).toBeUndefined();
    });
  });

  // 14. guest.network.public-listeners
  describe("guest.network.public-listeners", () => {
    test("fires when public listeners exist", () => {
      const s = baseSnapshot();
      s.network.publicListeningSockets = [
        {
          protocol: "tcp", family: "ipv4", state: "LISTEN", host: "0.0.0.0", port: 80,
          localAddress: "0.0.0.0:80", bindScope: "wildcard", reachability: "wildcard",
          raw: "tcp LISTEN 0 128 0.0.0.0:80", collectedFrom: "ss -H -lntup", parser: "ss",
          observedAt: s.collectedAt
        }
      ];
      const f = findByRule(s, "guest.network.public-listeners");
      expect(f).toBeDefined();
      expect(f!.confidence).toBe("authoritative");
    });

    test("does not fire when no public listeners", () => {
      expect(findByRule(baseSnapshot(), "guest.network.public-listeners")).toBeUndefined();
    });
  });

  // 15. guesthost.network.metadata-route
  describe("guesthost.network.metadata-route", () => {
    test("fires when metadata route is present", () => {
      const s = baseSnapshot();
      s.network.metadataRoutePresent = true;
      s.network.routes.push({
        raw: "169.254.169.254 via 10.0.2.2 dev eth0",
        destination: "169.254.169.254",
        via: "10.0.2.2",
        device: "eth0",
        scope: "other",
        observedAt: s.collectedAt,
        collectedFrom: "ip route show"
      });
      const f = findByRule(s, "guesthost.network.metadata-route");
      expect(f).toBeDefined();
      expect(f!.boundary).toBe("guest-host interface");
    });

    test("does not fire when no metadata route", () => {
      expect(findByRule(baseSnapshot(), "guesthost.network.metadata-route")).toBeUndefined();
    });
  });

  // 16. guest.files.world-writable-sensitive
  describe("guest.files.world-writable-sensitive", () => {
    test("fires when permission issues exist", () => {
      const s = baseSnapshot();
      s.filePermissionIssues = [
        { path: "/etc/shadow", mode: "0666", reason: "world-writable", observedAt: s.collectedAt, collectedFrom: "stat" }
      ];
      const f = findByRule(s, "guest.files.world-writable-sensitive");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("medium");
    });

    test("does not fire when no permission issues", () => {
      expect(findByRule(baseSnapshot(), "guest.files.world-writable-sensitive")).toBeUndefined();
    });
  });

  // 17. guest.packages.advisory-match
  describe("guest.packages.advisory-match", () => {
    test("fires for each vulnerable package", () => {
      const s = baseSnapshot();
      s.vulnerabilities = [
        { packageName: "openssl", summary: "CVE example", severity: "high", cves: ["CVE-2025-0001"], source: "bundle" }
      ];
      const f = findByRule(s, "guest.packages.advisory-match");
      expect(f).toBeDefined();
      expect(f!.id).toBe("advisory-openssl");
    });

    test("does not fire when no vulnerabilities", () => {
      expect(findByRule(baseSnapshot(), "guest.packages.advisory-match")).toBeUndefined();
    });
  });

  // 18. guest.advisory-bundle.stale
  describe("guest.advisory-bundle.stale", () => {
    test("fires when bundle is stale", () => {
      const s = baseSnapshot();
      s.advisoryBundle = { ...s.advisoryBundle!, stale: true };
      const f = findByRule(s, "guest.advisory-bundle.stale");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("medium");
    });

    test("does not fire when bundle is fresh", () => {
      expect(findByRule(baseSnapshot(), "guest.advisory-bundle.stale")).toBeUndefined();
    });
  });

  // 19. guest.advisory-bundle.unverified
  describe("guest.advisory-bundle.unverified", () => {
    test("fires when bundle is present but unverified and not stale", () => {
      const s = baseSnapshot();
      s.advisoryBundle = { ...s.advisoryBundle!, verified: false, stale: false };
      const f = findByRule(s, "guest.advisory-bundle.unverified");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("low");
    });

    test("does not fire when bundle is verified", () => {
      expect(findByRule(baseSnapshot(), "guest.advisory-bundle.unverified")).toBeUndefined();
    });

    test("does not fire when bundle is stale (stale check takes priority)", () => {
      const s = baseSnapshot();
      s.advisoryBundle = { ...s.advisoryBundle!, verified: false, stale: true };
      expect(findByRule(s, "guest.advisory-bundle.unverified")).toBeUndefined();
    });
  });

  // 20. guest.attack-path.exposed-service-bridge
  describe("guest.attack-path.exposed-service-bridge", () => {
    test("fires when all three signals are present", () => {
      const s = baseSnapshot();
      s.network.publicListeningSockets = [
        {
          protocol: "tcp", family: "ipv4", state: "LISTEN", host: "0.0.0.0", port: 8080,
          localAddress: "0.0.0.0:8080", bindScope: "wildcard", reachability: "wildcard",
          raw: "tcp LISTEN 0 128 0.0.0.0:8080", collectedFrom: "ss -H -lntup", parser: "ss",
          observedAt: s.collectedAt
        }
      ];
      s.security.firewall.defaultDenyInbound = false;
      s.network.bridgeLikely = true;
      const f = findByRule(s, "guest.attack-path.exposed-service-bridge");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("critical");
      expect(f!.confidence).toBe("inferred");
    });

    test("does not fire when firewall has default deny", () => {
      const s = baseSnapshot();
      s.network.publicListeningSockets = [
        {
          protocol: "tcp", family: "ipv4", state: "LISTEN", host: "0.0.0.0", port: 8080,
          localAddress: "0.0.0.0:8080", bindScope: "wildcard", reachability: "wildcard",
          raw: "tcp LISTEN 0 128 0.0.0.0:8080", collectedFrom: "ss -H -lntup", parser: "ss",
          observedAt: s.collectedAt
        }
      ];
      s.network.bridgeLikely = true;
      // defaultDenyInbound is already true in baseSnapshot
      expect(findByRule(s, "guest.attack-path.exposed-service-bridge")).toBeUndefined();
    });

    test("does not fire when no public listeners", () => {
      const s = baseSnapshot();
      s.security.firewall.defaultDenyInbound = false;
      s.network.bridgeLikely = true;
      expect(findByRule(s, "guest.attack-path.exposed-service-bridge")).toBeUndefined();
    });
  });

  // 21. host.unverifiable.libvirt-launch (always fires)
  describe("host.unverifiable.libvirt-launch", () => {
    test("always emits the finding", () => {
      const f = findByRule(baseSnapshot(), "host.unverifiable.libvirt-launch");
      expect(f).toBeDefined();
      expect(f!.confidence).toBe("unverifiable");
      expect(f!.boundary).toBe("host-unverifiable");
      expect(f!.severity).toBe("info");
    });
  });

  // 22. host.unverifiable.storage-and-dma (always fires)
  describe("host.unverifiable.storage-and-dma", () => {
    test("always emits the finding", () => {
      const f = findByRule(baseSnapshot(), "host.unverifiable.storage-and-dma");
      expect(f).toBeDefined();
      expect(f!.confidence).toBe("unverifiable");
      expect(f!.boundary).toBe("host-unverifiable");
      expect(f!.severity).toBe("info");
    });
  });

  // 23. guest-host.nested-virt.exposed
  describe("guest-host.nested-virt.exposed", () => {
    test("fires when nested virt is exposed (kvm_intel)", () => {
      const s = baseSnapshot();
      s.virtualization.nestedVirtExposed = true;
      const f = findByRule(s, "guest-host.nested-virt.exposed");
      expect(f).toBeDefined();
      expect(f!.boundary).toBe("guest-host interface");
      expect(f!.confidence).toBe("authoritative");
      expect(f!.severity).toBe("high");
    });

    test("does not fire when nested virt is not exposed", () => {
      expect(findByRule(baseSnapshot(), "guest-host.nested-virt.exposed")).toBeUndefined();
    });

    test("high-isolation bumps severity to critical", () => {
      const s = baseSnapshot();
      s.virtualization.nestedVirtExposed = true;
      const f = runChecks(s, "high-isolation").find((f) => f.ruleId === "guest-host.nested-virt.exposed");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("critical");
    });

    test("paranoid-lab bumps severity to critical", () => {
      const s = baseSnapshot();
      s.virtualization.nestedVirtExposed = true;
      const f = runChecks(s, "paranoid-lab").find((f) => f.ruleId === "guest-host.nested-virt.exposed");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("critical");
    });
  });

  // 24. guest.ksm.active
  describe("guest.ksm.active", () => {
    test("fires when KSM is active", () => {
      const s = baseSnapshot();
      s.virtualization.ksmActive = true;
      const f = findByRule(s, "guest.ksm.active");
      expect(f).toBeDefined();
      expect(f!.boundary).toBe("guest");
      expect(f!.confidence).toBe("authoritative");
    });

    test("does not fire when KSM is not active", () => {
      expect(findByRule(baseSnapshot(), "guest.ksm.active")).toBeUndefined();
    });
  });

  // 25. guesthost.balloon.present and guesthost.balloon.active
  describe("guesthost.balloon detection", () => {
    test("fires balloon.present when driver is loaded", () => {
      const s = baseSnapshot();
      s.virtualization.balloonDriverPresent = true;
      const f = findByRule(s, "guesthost.balloon.present");
      expect(f).toBeDefined();
      expect(f!.boundary).toBe("guest-host interface");
      expect(f!.confidence).toBe("authoritative");
    });

    test("fires balloon.active when balloon is adjusting memory", () => {
      const s = baseSnapshot();
      s.virtualization.balloonActiveAdjusting = true;
      const f = findByRule(s, "guesthost.balloon.active");
      expect(f).toBeDefined();
      expect(f!.boundary).toBe("guest-host interface");
      expect(f!.confidence).toBe("inferred");
    });

    test("both findings can fire together", () => {
      const s = baseSnapshot();
      s.virtualization.balloonDriverPresent = true;
      s.virtualization.balloonActiveAdjusting = true;
      const findings = runChecks(s, "balanced");
      const present = findings.find((f) => f.ruleId === "guesthost.balloon.present");
      const active = findings.find((f) => f.ruleId === "guesthost.balloon.active");
      expect(present).toBeDefined();
      expect(active).toBeDefined();
    });

    test("does not fire when balloon not present", () => {
      expect(findByRule(baseSnapshot(), "guesthost.balloon.present")).toBeUndefined();
      expect(findByRule(baseSnapshot(), "guesthost.balloon.active")).toBeUndefined();
    });
  });

  // Profile severity adjustments
  describe("profile severity adjustments", () => {
    test("high-isolation bumps guest-host interface findings", () => {
      const s = baseSnapshot();
      s.virtualization.sharedFolderMounts = [
        { mountPoint: "/mnt/share", fsType: "virtiofs", source: "share", options: ["rw"], observedAt: s.collectedAt, collectedFrom: "/proc/mounts" }
      ];
      const balanced = runChecks(s, "balanced").find((f) => f.ruleId === "guesthost.shared-folders.present");
      const highIso = runChecks(s, "high-isolation").find((f) => f.ruleId === "guesthost.shared-folders.present");
      expect(balanced).toBeDefined();
      expect(highIso).toBeDefined();
      // high-isolation bumps severity for guest-host interface + leakageRisk
      const severityOrder = ["info", "low", "medium", "high", "critical"];
      expect(severityOrder.indexOf(highIso!.severity)).toBeGreaterThanOrEqual(severityOrder.indexOf(balanced!.severity));
    });
  });
});
