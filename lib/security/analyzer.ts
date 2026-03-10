import { buildPostureSummary } from "@/lib/security/posture";
import { buildRemediationAction } from "@/lib/security/remediation";
import type { Evidence, Finding, PostureSummary, ScanSnapshot, Severity, StoredScan } from "@/lib/types";

function evidence(id: string, label: string, detail: string, source: string): Evidence {
  return { id, label, detail, source };
}

function createFinding(input: Omit<Finding, "createdAt">): Finding {
  return {
    ...input,
    createdAt: new Date().toISOString()
  };
}

function severityRank(severity: Severity): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(severity);
}

function buildFindings(snapshot: ScanSnapshot): Finding[] {
  const findings: Finding[] = [];

  const selinuxOff = snapshot.security.lsm.selinuxMode !== "enforcing";
  const appArmorOff = !snapshot.security.lsm.appArmorEnabled;
  if (selinuxOff && appArmorOff) {
    findings.push(
      createFinding({
        id: "guest-lsm-not-enforcing",
        title: "Mandatory access control is not enforcing",
        summary: "Neither SELinux enforcing mode nor AppArmor enforcement is visible in the guest.",
        severity: "high",
        confidence: "authoritative",
        boundary: "guest",
        categories: ["guestHardening"],
        evidence: [
          evidence("selinux", "SELinux mode", snapshot.security.lsm.selinuxMode, "/sys/fs/selinux/enforce"),
          evidence("apparmor", "AppArmor enabled", String(snapshot.security.lsm.appArmorEnabled), "/sys/module/apparmor/parameters/enabled")
        ],
        rationale: "A non-enforcing LSM materially weakens containment inside the guest.",
        remediation: [
          {
            id: "manual-enable-lsm",
            title: "Enable an enforcing LSM",
            description: "Boot with SELinux enforcing or load AppArmor profiles appropriate for the guest workload.",
            requiresRoot: true,
            safeForAutomationLater: false,
            mode: "manual",
            commands: ["Review distro-specific SELinux or AppArmor enablement steps before changing boot policy."]
          }
        ],
        safeForAutomationLater: false
      })
    );
  }

  if (!snapshot.security.firewall.rulesPresent) {
    findings.push(
      createFinding({
        id: "guest-firewall-missing",
        title: "Firewall rules are not loaded",
        summary: "The guest does not appear to have an active nftables or iptables policy.",
        severity: "high",
        confidence: "authoritative",
        boundary: "guest",
        categories: ["guestHardening", "exposureSurface", "remediationReadiness"],
        evidence: [
          evidence("firewall-backend", "Firewall backend", snapshot.security.firewall.backend, "collector"),
          evidence("firewall-rules", "Rules present", String(snapshot.security.firewall.rulesPresent), "collector")
        ],
        rationale: "A missing guest firewall increases exposure regardless of whether the host uses NAT or bridge networking.",
        remediation: [buildRemediationAction("enable-firewall", "Enable a host-local firewall", "Enable the guest firewall with a default-deny inbound posture.", snapshot, true, true)],
        safeForAutomationLater: true
      })
    );
  } else if (!snapshot.security.firewall.defaultDenyInbound) {
    findings.push(
      createFinding({
        id: "guest-firewall-not-default-deny",
        title: "Firewall does not show a default-deny inbound policy",
        summary: "Rules are present, but the collector did not observe an inbound drop or reject default policy.",
        severity: "medium",
        confidence: "authoritative",
        boundary: "guest",
        categories: ["guestHardening", "exposureSurface"],
        evidence: snapshot.security.firewall.rawSummary.slice(0, 3).map((line, index) =>
          evidence(`firewall-summary-${index}`, "Firewall summary", line, snapshot.security.firewall.backend)
        ),
        rationale: "Default-allow firewalls are easy to drift into insecure service exposure.",
        remediation: [buildRemediationAction("enable-firewall", "Tighten inbound firewall policy", "Apply a default-deny inbound firewall policy where supported.", snapshot, true, false)],
        safeForAutomationLater: false
      })
    );
  }

  if (snapshot.security.ssh.installed) {
    const weakSettings = [
      snapshot.security.ssh.passwordAuthentication && snapshot.security.ssh.passwordAuthentication.toLowerCase() !== "no"
        ? `PasswordAuthentication=${snapshot.security.ssh.passwordAuthentication}`
        : null,
      snapshot.security.ssh.permitRootLogin && snapshot.security.ssh.permitRootLogin.toLowerCase() !== "no"
        ? `PermitRootLogin=${snapshot.security.ssh.permitRootLogin}`
        : null,
      snapshot.security.ssh.x11Forwarding && snapshot.security.ssh.x11Forwarding.toLowerCase() !== "no"
        ? `X11Forwarding=${snapshot.security.ssh.x11Forwarding}`
        : null
    ].filter(Boolean) as string[];

    if (weakSettings.length > 0) {
      findings.push(
        createFinding({
          id: "ssh-configuration-weak",
          title: "SSH daemon exposes high-risk defaults",
          summary: "The guest SSH configuration permits settings that weaken isolation or increase remote attack surface.",
          severity: "high",
          confidence: "authoritative",
          boundary: "guest",
          categories: ["guestHardening", "exposureSurface", "remediationReadiness"],
          evidence: weakSettings.map((setting, index) => evidence(`ssh-${index}`, "SSH setting", setting, "/etc/ssh/sshd_config")),
          rationale: "Password logins, root SSH, and X11 forwarding all expand attack and leakage paths.",
          remediation: [
            {
              id: "manual-harden-ssh",
              title: "Harden SSH configuration",
              description: "Disable password login, root login, and X11 forwarding in sshd_config, then restart sshd.",
              requiresRoot: true,
              safeForAutomationLater: false,
              mode: "manual",
              commands: ["Set PasswordAuthentication no, PermitRootLogin no, X11Forwarding no, then reload sshd."]
            }
          ],
          safeForAutomationLater: false
        })
      );
    }
  }

  if (snapshot.security.sudoers.nopasswdEntries.length > 0) {
    findings.push(
      createFinding({
        id: "sudoers-nopasswd",
        title: "Passwordless sudo entries were found",
        summary: "The guest sudoers configuration contains NOPASSWD rules.",
        severity: "medium",
        confidence: "authoritative",
        boundary: "guest",
        categories: ["guestHardening", "remediationReadiness"],
        evidence: snapshot.security.sudoers.nopasswdEntries.slice(0, 5).map((entry, index) =>
          evidence(`sudoers-${index}`, "NOPASSWD entry", entry, "/etc/sudoers")
        ),
        rationale: "Passwordless privilege escalation weakens compartmentalization inside the guest.",
        remediation: [
          {
            id: "manual-tighten-sudoers",
            title: "Review sudoers NOPASSWD rules",
            description: "Remove unnecessary NOPASSWD rules and restrict sudo to explicit administrator groups.",
            requiresRoot: true,
            safeForAutomationLater: false,
            mode: "manual",
            commands: ["Audit /etc/sudoers and /etc/sudoers.d/* for NOPASSWD directives."]
          }
        ],
        safeForAutomationLater: false
      })
    );
  }

  if (snapshot.virtualization.sharedFolderMounts.length > 0) {
    findings.push(
      createFinding({
        id: "shared-folder-mounts-detected",
        title: "Shared folder mounts bridge guest and host storage",
        summary: "virtiofs or 9p shared mounts are present inside the guest.",
        severity: "high",
        confidence: "authoritative",
        boundary: "guest-host interface",
        categories: ["leakageRisk", "exposureSurface", "remediationReadiness"],
        evidence: snapshot.virtualization.sharedFolderMounts.map((mount, index) =>
          evidence(
            `shared-mount-${index}`,
            `${mount.fsType} mount`,
            `${mount.source} -> ${mount.mountPoint}`,
            "/proc/mounts"
          )
        ),
        rationale: "Shared folders create a direct host-guest data path that undermines compartmentalization.",
        remediation: [buildRemediationAction("unmount-shared-folders", "Unmount shared folders", "Unmount all guest-visible shared folder mounts.", snapshot, true, true)],
        safeForAutomationLater: true
      })
    );
  }

  if (snapshot.virtualization.qemuGuestAgent) {
    findings.push(
      createFinding({
        id: "qemu-guest-agent-present",
        title: "qemu-guest-agent is installed or reachable",
        summary: "The guest exposes a management surface to the host through qemu-guest-agent.",
        severity: "medium",
        confidence: "inferred",
        boundary: "guest-host interface",
        categories: ["leakageRisk", "exposureSurface", "remediationReadiness"],
        evidence: [
          evidence("guest-agent-device", "Guest agent channel", String(snapshot.virtualization.qemuGuestAgent), "/dev/virtio-ports/org.qemu.guest_agent.0")
        ],
        rationale: "Guest agent channels are useful operationally but reduce separation between host workflows and guest autonomy.",
        remediation: [buildRemediationAction("disable-qemu-guest-agent", "Disable qemu-guest-agent", "Disable guest agent integration unless host orchestration requires it.", snapshot, true, true)],
        safeForAutomationLater: true
      })
    );
  }

  if (snapshot.virtualization.spiceVdagent) {
    findings.push(
      createFinding({
        id: "spice-vdagent-present",
        title: "SPICE vdagent introduces clipboard and desktop integration surfaces",
        summary: "SPICE guest integration software is active in the guest.",
        severity: "medium",
        confidence: "inferred",
        boundary: "guest-host interface",
        categories: ["leakageRisk", "remediationReadiness"],
        evidence: [
          evidence("spice-vdagent", "SPICE agent", String(snapshot.virtualization.spiceVdagent), "systemctl/packages")
        ],
        rationale: "Clipboard and desktop integrations are convenient but materially increase data leakage risk.",
        remediation: [buildRemediationAction("disable-spice-vdagent", "Disable SPICE vdagent", "Disable desktop integration for higher-isolation profiles.", snapshot, true, true)],
        safeForAutomationLater: true
      })
    );
  }

  if (snapshot.virtualization.vsockEnabled) {
    findings.push(
      createFinding({
        id: "vsock-enabled",
        title: "AF_VSOCK support is visible in the guest",
        summary: "The guest can likely speak to the host or sibling services over AF_VSOCK.",
        severity: "medium",
        confidence: "inferred",
        boundary: "guest-host interface",
        categories: ["leakageRisk", "exposureSurface"],
        evidence: [
          evidence("vsock", "vsock enabled", String(snapshot.virtualization.vsockEnabled), "/dev/vsock")
        ],
        rationale: "AF_VSOCK is a useful control path, but it adds a host-adjacent communication channel that should be justified.",
        remediation: [
          {
            id: "manual-review-vsock",
            title: "Review vsock usage",
            description: "Disable guest workloads that depend on vsock unless they are explicitly required.",
            requiresRoot: true,
            safeForAutomationLater: false,
            mode: "manual",
            commands: ["Review host XML and guest services for AF_VSOCK dependencies before removal."]
          }
        ],
        safeForAutomationLater: false
      })
    );
  }

  const discoveryService = snapshot.services.find((service) => service.name === "avahi-daemon.service" && service.active);
  if (discoveryService) {
    findings.push(
      createFinding({
        id: "avahi-discovery-enabled",
        title: "mDNS discovery is active",
        summary: "avahi-daemon is active, which increases discovery and naming leakage on local networks.",
        severity: "medium",
        confidence: "authoritative",
        boundary: "guest",
        categories: ["exposureSurface", "leakageRisk", "remediationReadiness"],
        evidence: [evidence("avahi-service", "Active service", discoveryService.name, "systemctl")],
        rationale: "Discovery protocols expose metadata and make accidental service reachability easier.",
        remediation: [buildRemediationAction("disable-avahi-daemon", "Disable avahi-daemon", "Disable mDNS and local service discovery inside the guest.", snapshot, true, true)],
        safeForAutomationLater: true
      })
    );
  }

  if (snapshot.network.publicListeningSockets.length > 0) {
    findings.push(
      createFinding({
        id: "public-listeners-present",
        title: "Guest services listen on non-loopback addresses",
        summary: "One or more sockets are bound beyond localhost.",
        severity: snapshot.network.publicListeningSockets.length > 3 ? "high" : "medium",
        confidence: "authoritative",
        boundary: "guest",
        categories: ["exposureSurface", "guestHardening"],
        evidence: snapshot.network.publicListeningSockets.slice(0, 10).map((socket, index) =>
          evidence(`listener-${index}`, "Listening socket", socket.raw, "ss -lntu")
        ),
        rationale: "If the host uses bridged networking or permissive NAT rules, these services become remotely reachable.",
        remediation: [
          {
            id: "manual-review-listeners",
            title: "Review listening services",
            description: "Restrict services to localhost, disable unneeded daemons, or enforce firewall rules around them.",
            requiresRoot: true,
            safeForAutomationLater: false,
            mode: "manual",
            commands: ["Audit systemd units and service bind addresses for exposed sockets."]
          }
        ],
        safeForAutomationLater: false
      })
    );
  }

  if (snapshot.network.metadataRoutePresent) {
    findings.push(
      createFinding({
        id: "metadata-route-present",
        title: "Cloud-style metadata route is present",
        summary: "The guest routing table references 169.254.169.254.",
        severity: "high",
        confidence: "inferred",
        boundary: "guest-host interface",
        categories: ["exposureSurface", "leakageRisk"],
        evidence: snapshot.network.routes
          .filter((route) => route.includes("169.254.169.254"))
          .map((route, index) => evidence(`metadata-route-${index}`, "Metadata route", route, "ip route")),
        rationale: "Metadata endpoints are a frequent source of credential and environment leakage.",
        remediation: [
          {
            id: "manual-block-metadata",
            title: "Block metadata endpoint access",
            description: "Add guest firewall rules to deny access to 169.254.169.254 unless explicitly required.",
            requiresRoot: true,
            safeForAutomationLater: false,
            mode: "manual",
            commands: ["Add an outbound deny rule for 169.254.169.254 in the guest firewall."]
          }
        ],
        safeForAutomationLater: false
      })
    );
  }

  if (snapshot.filePermissionIssues.length > 0) {
    findings.push(
      createFinding({
        id: "world-writable-sensitive-paths",
        title: "Sensitive paths include world-writable entries",
        summary: "World-writable files or directories were found in privileged paths.",
        severity: "medium",
        confidence: "authoritative",
        boundary: "guest",
        categories: ["guestHardening", "remediationReadiness"],
        evidence: snapshot.filePermissionIssues.slice(0, 10).map((issue, index) =>
          evidence(`perm-${index}`, "File permission issue", `${issue.path} (${issue.mode})`, "filesystem")
        ),
        rationale: "Weak file permissions can turn minor service compromise into full guest persistence.",
        remediation: [
          {
            id: "manual-fix-permissions",
            title: "Correct file permissions",
            description: "Remove world-writable permissions from privileged files and directories that do not need them.",
            requiresRoot: true,
            safeForAutomationLater: false,
            mode: "manual",
            commands: ["Review and chmod the flagged paths after validating intended ownership."]
          }
        ],
        safeForAutomationLater: false
      })
    );
  }

  for (const vulnerability of snapshot.vulnerabilities) {
    findings.push(
      createFinding({
        id: `advisory-${vulnerability.packageName}`,
        title: `Installed package matches advisory: ${vulnerability.packageName}`,
        summary: vulnerability.summary,
        severity: vulnerability.severity,
        confidence: snapshot.advisoryBundle?.stale ? "inferred" : "authoritative",
        boundary: "guest",
        categories: ["guestHardening", "remediationReadiness"],
        evidence: [
          evidence("package", "Package match", vulnerability.packageName, snapshot.advisoryBundle?.source ?? "advisory-bundle"),
          evidence("bundle", "Advisory source", snapshot.advisoryBundle?.bundleId ?? "none", "advisory-bundle")
        ],
        rationale: "Package-level advisories identify software that may need patching or removal inside the guest.",
        remediation: [
          {
            id: `manual-patch-${vulnerability.packageName}`,
            title: `Patch or remove ${vulnerability.packageName}`,
            description: "Apply vendor updates or remove the package if it is not required for the guest role.",
            requiresRoot: true,
            safeForAutomationLater: false,
            mode: "manual",
            commands: [`Use the guest package manager to patch or remove ${vulnerability.packageName}.`]
          }
        ],
        safeForAutomationLater: false
      })
    );
  }

  if (snapshot.advisoryBundle?.stale) {
    findings.push(
      createFinding({
        id: "advisory-bundle-stale",
        title: "Offline advisory bundle is stale",
        summary: "Package risk evaluation is based on an outdated advisory bundle.",
        severity: "medium",
        confidence: "authoritative",
        boundary: "guest",
        categories: ["remediationReadiness"],
        evidence: [
          evidence("bundle-age", "Bundle generated at", snapshot.advisoryBundle.generatedAt, "advisory-bundle")
        ],
        rationale: "Stale advisory data undermines the usefulness of offline vulnerability analysis.",
        remediation: [
          {
            id: "manual-import-advisories",
            title: "Import a newer advisory bundle",
            description: "Use the offline import command to replace the advisory bundle with a newer signed copy.",
            requiresRoot: false,
            safeForAutomationLater: false,
            mode: "manual",
            commands: ["bun run advisories:import /path/to/advisories.bundle.json"]
          }
        ],
        safeForAutomationLater: false
      })
    );
  }

  const unverifiableFindings: Finding[] = [
    createFinding({
      id: "host-libvirt-xml-unverifiable",
      title: "Host libvirt and QEMU launch isolation cannot be verified from the guest",
      summary: "The guest cannot directly inspect libvirt XML, QEMU flags, or host-side tap/bridge policy.",
      severity: "info",
      confidence: "unverifiable",
      boundary: "host-unverifiable",
      categories: ["unverifiableHostControls"],
      evidence: [evidence("visibility", "Visibility limit", "Host launch configuration is not observable from inside the guest.", "trust-model")],
      rationale: "A guest-resident tool must not claim certainty about host-side isolation controls.",
      remediation: [],
      safeForAutomationLater: false
    }),
    createFinding({
      id: "host-confinement-unverifiable",
      title: "Host confinement labels and cgroup policy remain unverifiable",
      summary: "sVirt, SELinux/AppArmor labels, and host cgroup controls are outside the guest trust boundary.",
      severity: "info",
      confidence: "unverifiable",
      boundary: "host-unverifiable",
      categories: ["unverifiableHostControls"],
      evidence: [evidence("visibility", "Visibility limit", "Host mandatory access control and cgroup state are not guest-visible.", "trust-model")],
      rationale: "Isolation claims require host inspection or attestation, neither of which exists in the strict guest-only design.",
      remediation: [],
      safeForAutomationLater: false
    }),
    createFinding({
      id: "host-storage-unverifiable",
      title: "Host snapshot storage and DMA posture cannot be certified",
      summary: "The guest cannot determine how disk images, snapshots, or IOMMU protections are configured on the host.",
      severity: "info",
      confidence: "unverifiable",
      boundary: "host-unverifiable",
      categories: ["unverifiableHostControls"],
      evidence: [evidence("visibility", "Visibility limit", "Host storage permissions and DMA protections are outside guest visibility.", "trust-model")],
      rationale: "These controls materially affect isolation but require host-side verification.",
      remediation: [],
      safeForAutomationLater: false
    })
  ];

  findings.push(...unverifiableFindings);

  return findings.sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
}

export function analyzeSnapshot(snapshot: ScanSnapshot): StoredScan {
  const findings = buildFindings(snapshot);
  const posture: PostureSummary = buildPostureSummary(findings);
  return {
    scanId: snapshot.id,
    snapshot,
    findings,
    posture
  };
}

