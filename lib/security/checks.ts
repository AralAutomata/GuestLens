import { createHash } from "node:crypto";

import { buildRemediationAction } from "@/lib/security/remediation";
import type {
  AffectedBoundary,
  CheckResult,
  ConfidenceLevel,
  EvidenceRecord,
  Finding,
  FindingGroup,
  PolicyProfile,
  PostureCategory,
  RiskFactor,
  ScanSnapshot,
  Severity
} from "@/lib/types";

interface CheckContext {
  snapshot: ScanSnapshot;
  profile: PolicyProfile;
}

interface CheckDefinition {
  run(context: CheckContext): CheckResult[];
}

function severityRank(severity: Severity): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(severity);
}

function confidenceRank(confidence: ConfidenceLevel): number {
  return ["unverifiable", "inferred", "authoritative"].indexOf(confidence);
}

function bumpSeverity(severity: Severity, steps = 1): Severity {
  const ordered: Severity[] = ["info", "low", "medium", "high", "critical"];
  const nextIndex = Math.min(ordered.length - 1, ordered.indexOf(severity) + steps);
  return ordered[nextIndex];
}

function profileAdjustedSeverity(
  profile: PolicyProfile,
  severity: Severity,
  boundary: AffectedBoundary,
  categories: PostureCategory[]
): Severity {
  if (profile === "balanced") {
    return severity;
  }
  if (profile === "high-isolation") {
    if (boundary === "guest-host interface" || categories.includes("leakageRisk")) {
      return bumpSeverity(severity);
    }
    return severity;
  }
  if (boundary === "guest-host interface" || categories.includes("leakageRisk") || categories.includes("exposureSurface")) {
    return bumpSeverity(severity);
  }
  return bumpSeverity(severity, categories.includes("guestHardening") ? 1 : 0);
}

function evidence(
  snapshot: ScanSnapshot,
  input: {
    id: string;
    label: string;
    kind: string;
    value: string;
    source: string;
    pathOrCommand: string;
    interpretation: string;
    confidenceBasis: string;
  }
): EvidenceRecord {
  return {
    ...input,
    collector: snapshot.collectorVersion,
    observedAt: snapshot.collectedAt
  };
}

function riskFactor(
  id: string,
  label: string,
  detail: string,
  severity: Severity,
  boundary: AffectedBoundary
): RiskFactor {
  return { id, label, detail, severity, boundary };
}

function createFinding(
  snapshot: ScanSnapshot,
  profile: PolicyProfile,
  input: Omit<
    Finding,
    | "createdAt"
    | "profile"
    | "fingerprint"
    | "subcategory"
    | "remediationPreconditions"
    | "suppressionEligible"
    | "suppressed"
    | "suppression"
  > & {
    subcategory?: string;
    remediationPreconditions?: string[];
    suppressionEligible?: boolean;
  }
): Finding {
  const fingerprintPayload = JSON.stringify({
    ruleId: input.ruleId,
    boundary: input.boundary,
    impactedSurfaces: [...input.impactedSurfaces].sort(),
    evidence: input.evidence.map((item) => ({
      label: item.label,
      value: item.value,
      source: item.source,
      pathOrCommand: item.pathOrCommand
    }))
  });

  return {
    ...input,
    subcategory: input.subcategory ?? input.groupKey,
    fingerprint: createHash("sha256").update(fingerprintPayload).digest("hex"),
    profile,
    remediationPreconditions: input.remediationPreconditions ?? [],
    suppressionEligible: input.suppressionEligible ?? input.boundary !== "host-unverifiable",
    suppressed: false,
    suppression: null,
    createdAt: new Date().toISOString()
  };
}

function sshDirectiveValue(snapshot: ScanSnapshot, key: string): string | undefined {
  for (let index = snapshot.security.ssh.directives.length - 1; index >= 0; index -= 1) {
    const directive = snapshot.security.ssh.directives[index];
    if (directive.key.toLowerCase() === key.toLowerCase()) {
      return directive.value;
    }
  }
  return undefined;
}

const checks: CheckDefinition[] = [
  {
    run({ snapshot, profile }) {
      if (snapshot.security.lsm.selinuxMode === "enforcing" || snapshot.security.lsm.appArmorEnabled) {
        return [];
      }

      const lsmEvidence = [
        evidence(snapshot, {
          id: "selinux",
          label: "SELinux mode",
          kind: "kernel-state",
          value: snapshot.security.lsm.selinuxMode,
          source: "/sys/fs/selinux/enforce",
          pathOrCommand: "cat /sys/fs/selinux/enforce",
          interpretation: snapshot.security.lsm.selinuxMode === "permissive"
            ? "SELinux is installed but not enforcing."
            : "SELinux is not present on this system.",
          confidenceBasis: "Direct kernel state"
        }),
        evidence(snapshot, {
          id: "apparmor",
          label: "AppArmor enabled",
          kind: "kernel-state",
          value: String(snapshot.security.lsm.appArmorEnabled),
          source: "/sys/module/apparmor/parameters/enabled",
          pathOrCommand: "cat /sys/module/apparmor/parameters/enabled",
          interpretation: "AppArmor enforcement is not active.",
          confidenceBasis: "Direct kernel state"
        })
      ];

      if (snapshot.security.lsm.selinuxMode === "permissive") {
        return [
          {
            finding: createFinding(snapshot, profile, {
              id: "guest-lsm-not-enforcing",
              ruleId: "guest.lsm.not-enforcing",
              groupKey: "guest-hardening",
              title: "Mandatory access control is not enforcing",
              summary: "SELinux is installed but running in permissive mode; policy violations are logged but not blocked.",
              severity: profileAdjustedSeverity(profile, "high", "guest", ["guestHardening"]),
              confidence: "authoritative",
              certaintyReason: "The guest can directly read SELinux and AppArmor kernel state.",
              boundary: "guest",
              categories: ["guestHardening"],
              impactedSurfaces: ["kernel policy", "process confinement"],
              evidence: lsmEvidence,
              rationale: "Permissive mode logs violations but does not enforce them, leaving containment inactive.",
              operatorImpact: "Privilege separation inside the guest is materially weaker.",
              falsePositiveGuidance: "Ignore only if the workload intentionally runs in permissive mode for policy development.",
              remediation: [
                {
                  id: "manual-enforce-selinux",
                  title: "Set SELinux to enforcing mode",
                  description: "Switch SELinux from permissive to enforcing to activate policy enforcement.",
                  requiresRoot: true,
                  safeForAutomationLater: false,
                  mode: "manual",
                  commands: ["Set SELINUX=enforcing in /etc/selinux/config and reboot, or run setenforce 1 for immediate effect."]
                }
              ],
              riskFactors: [riskFactor("lsm", "Guest kernel policy", "SELinux is permissive, not enforcing.", "high", "guest")],
              relatedFindingIds: [],
              safeForAutomationLater: false
            })
          }
        ];
      }

      return [
        {
          finding: createFinding(snapshot, profile, {
            id: "guest-lsm-disabled",
            ruleId: "guest.lsm.disabled",
            groupKey: "guest-hardening",
            title: "No mandatory access control system is active",
            summary: "The guest has no enforcing SELinux or AppArmor policy; neither LSM is present.",
            severity: profileAdjustedSeverity(profile, "high", "guest", ["guestHardening"]),
            confidence: "authoritative",
            certaintyReason: "The guest can directly read SELinux and AppArmor kernel state.",
            boundary: "guest",
            categories: ["guestHardening"],
            impactedSurfaces: ["kernel policy", "process confinement"],
            evidence: lsmEvidence,
            rationale: "Without any LSM, a guest compromise has no kernel-backed containment barriers.",
            operatorImpact: "Privilege separation inside the guest is materially weaker.",
            falsePositiveGuidance: "Ignore only if the workload intentionally runs without SELinux/AppArmor and isolation is enforced elsewhere inside the guest.",
            remediation: [
              {
                id: "manual-install-lsm",
                title: "Install and enable an LSM",
                description: "Install and enable SELinux or AppArmor to provide mandatory access control for the guest workload.",
                requiresRoot: true,
                safeForAutomationLater: false,
                mode: "manual",
                commands: ["Review distro-specific SELinux or AppArmor installation and enablement before changing boot policy."]
              }
            ],
            riskFactors: [riskFactor("lsm", "Guest kernel policy", "No LSM is installed or active.", "high", "guest")],
            relatedFindingIds: [],
            safeForAutomationLater: false
          })
        }
      ];
    }
  },
  {
    run({ snapshot, profile }) {
      if (snapshot.security.firewall.inspectionAvailable === false) {
        return [
          {
            finding: createFinding(snapshot, profile, {
              id: "guest-firewall-visibility-limited",
              ruleId: "guest.firewall.visibility-limited",
              groupKey: "observability",
              title: "Firewall visibility is permission-limited",
              summary: "The guest appears to have firewall tooling, but process privileges were insufficient to read full ruleset state.",
              severity: profileAdjustedSeverity(profile, "low", "guest", ["observabilityConfidence", "exposureSurface"]),
              confidence: "inferred",
              certaintyReason:
                "The collector could not read backend firewall tables and therefore cannot prove default policy or rule coverage.",
              boundary: "guest",
              categories: ["observabilityConfidence", "exposureSurface"],
              impactedSurfaces: ["firewall telemetry"],
              evidence: [
                evidence(snapshot, {
                  id: "firewall-visibility",
                  label: "Firewall inspection error",
                  kind: "firewall",
                  value: snapshot.security.firewall.inspectionError ?? "permission-limited",
                  source: snapshot.security.firewall.source,
                  pathOrCommand: snapshot.security.firewall.collectedFrom,
                  interpretation: "Permission barriers prevented complete firewall inspection.",
                  confidenceBasis: "Tooling output error"
                })
              ],
              rationale: "Without backend visibility, exposure findings should be treated as indicative rather than definitive.",
              operatorImpact: "Run the scanner with privileged access or collect firewall policy via host-managed tools to confirm.",
              falsePositiveGuidance: "This is a tooling visibility limit, not proof of an unsafe policy.",
              remediation: [],
              riskFactors: [
                riskFactor("visibility", "Firewall inspection", "Firewall rules could not be read without elevated permissions.", "low", "guest")
              ],
              relatedFindingIds: [],
              safeForAutomationLater: false
            })
          }
        ];
      }

      if (!snapshot.security.firewall.rulesPresent) {
        return [
          {
            finding: createFinding(snapshot, profile, {
              id: "guest-firewall-missing",
              ruleId: "guest.firewall.missing",
              groupKey: "exposure-control",
              title: "Firewall rules are not loaded",
              summary: "The guest does not appear to have an active nftables or iptables policy.",
              severity: profileAdjustedSeverity(profile, "high", "guest", ["guestHardening", "exposureSurface"]),
              confidence: "authoritative",
              certaintyReason: "The guest directly inspected local firewall backends and found no active ruleset.",
              boundary: "guest",
              categories: ["guestHardening", "exposureSurface"],
              impactedSurfaces: ["inbound network policy", "service exposure"],
              evidence: [
                evidence(snapshot, {
                  id: "firewall-backend",
                  label: "Firewall backend",
                  kind: "firewall",
                  value: `${snapshot.security.firewall.backend}/${snapshot.security.firewall.manager}`,
                  source: snapshot.security.firewall.source,
                  pathOrCommand: snapshot.security.firewall.collectedFrom,
                  interpretation: "No active ruleset was detected.",
                  confidenceBasis: "Direct command output"
                })
              ],
              rationale: "A missing guest firewall removes an important control plane even when the hypervisor uses NAT.",
              operatorImpact: "Services can be reachable far more broadly than intended if they bind beyond localhost.",
              falsePositiveGuidance: "This is a weak signal only if the guest intentionally relies on host-only transport and every service binds to loopback.",
              remediation: [
                buildRemediationAction(
                  "enable-firewall",
                  "Enable a guest firewall",
                  "Enable a local firewall with a default-deny inbound posture.",
                  snapshot,
                  true,
                  true
                )
              ],
              riskFactors: [
                riskFactor("firewall", "Guest firewall absent", "No local firewall rules were detected.", "high", "guest")
              ],
              relatedFindingIds: [],
              safeForAutomationLater: true
            })
          }
        ];
      }

      const findings: CheckResult[] = [];

      if (!snapshot.security.firewall.defaultDenyInbound) {
        findings.push({
          finding: createFinding(snapshot, profile, {
            id: "guest-firewall-not-default-deny",
            ruleId: "guest.firewall.not-default-deny",
            groupKey: "exposure-control",
            title: "Firewall does not show a default-deny inbound policy",
            summary: "Rules are present, but the guest does not expose a clear drop or reject default for inbound traffic.",
            severity: profileAdjustedSeverity(profile, "medium", "guest", ["guestHardening", "exposureSurface"]),
            confidence: snapshot.security.firewall.inferenceQuality === "exact" ? "authoritative" : "inferred",
            certaintyReason:
              snapshot.security.firewall.inferenceQuality === "exact"
                ? "The guest directly observed the chain or hook policy."
                : "Rules exist, but the collector had to infer posture from an incomplete backend summary.",
            boundary: "guest",
            categories: ["guestHardening", "exposureSurface", "observabilityConfidence"],
            impactedSurfaces: ["inbound network policy"],
            evidence: snapshot.security.firewall.rawSummary.slice(0, 4).map((line, index) =>
              evidence(snapshot, {
                id: `firewall-${index}`,
                label: "Firewall summary",
                kind: "firewall",
                value: line,
                source: snapshot.security.firewall.source,
                pathOrCommand: snapshot.security.firewall.collectedFrom,
                interpretation: `Observed ${snapshot.security.firewall.backend} ruleset summary.`,
                confidenceBasis: snapshot.security.firewall.inferenceQuality
              })
            ),
            rationale: "A default-allow inbound stance makes accidental exposure drift much more likely.",
            operatorImpact: "Newly started services can become externally reachable without an explicit firewall change.",
            falsePositiveGuidance: "Treat this as heuristic if a higher-level firewall manager applies policy the collector could not parse cleanly.",
            remediation: [
              buildRemediationAction(
                "enable-firewall",
                "Tighten inbound firewall policy",
                "Apply a default-deny inbound policy in the guest firewall backend.",
                snapshot,
                true,
                false
              )
            ],
            riskFactors: [
              riskFactor("policy", "Inbound policy", "Inbound default deny was not confirmed.", "medium", "guest")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false
          })
        });
      }

      if (snapshot.security.firewall.inferenceQuality === "heuristic") {
        findings.push({
          finding: createFinding(snapshot, profile, {
            id: "guest-firewall-heuristic-visibility",
            ruleId: "guest.firewall.heuristic-visibility",
            groupKey: "observability",
            title: "Firewall posture is only partially observable",
            summary: "A firewall backend exists, but the collector could not conclusively derive a full policy posture.",
            severity: "low",
            confidence: "authoritative",
            certaintyReason: "The guest can see the raw ruleset, but policy interpretation remains heuristic.",
            boundary: "guest",
            categories: ["observabilityConfidence"],
            impactedSurfaces: ["firewall telemetry"],
            evidence: [
              evidence(snapshot, {
                id: "firewall-parser",
                label: "Inference quality",
                kind: "telemetry",
                value: snapshot.security.firewall.inferenceQuality,
                source: snapshot.security.firewall.source,
                pathOrCommand: snapshot.security.firewall.collectedFrom,
                interpretation: "Collector could not classify the firewall posture exactly.",
                confidenceBasis: "Collector parser result"
              })
            ],
            rationale: "Operators need to know when a policy conclusion is heuristic instead of exact.",
            operatorImpact: "Firewall findings should be reviewed alongside the raw ruleset summary.",
            falsePositiveGuidance: "This is expected on unusual firewall layouts or when a manager rewrites backend rules dynamically.",
            remediation: [],
            riskFactors: [
              riskFactor("visibility", "Telemetry ambiguity", "Firewall parsing is heuristic.", "low", "guest")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false
          })
        });
      }

      return findings;
    }
  },
  {
    run({ snapshot, profile }) {
      if (!snapshot.security.ssh.installed) {
        return [];
      }

      const weakSettings = [
        snapshot.security.ssh.passwordAuthentication && snapshot.security.ssh.passwordAuthentication.toLowerCase() !== "no"
          ? ["PasswordAuthentication", sshDirectiveValue(snapshot, "PasswordAuthentication") ?? snapshot.security.ssh.passwordAuthentication]
          : null,
        snapshot.security.ssh.permitRootLogin && snapshot.security.ssh.permitRootLogin.toLowerCase() !== "no"
          ? ["PermitRootLogin", sshDirectiveValue(snapshot, "PermitRootLogin") ?? snapshot.security.ssh.permitRootLogin]
          : null,
        snapshot.security.ssh.x11Forwarding && snapshot.security.ssh.x11Forwarding.toLowerCase() !== "no"
          ? ["X11Forwarding", sshDirectiveValue(snapshot, "X11Forwarding") ?? snapshot.security.ssh.x11Forwarding]
          : null
      ].filter(Boolean) as Array<[string, string]>;

      if (weakSettings.length === 0) {
        return [];
      }

      return [
        {
          finding: createFinding(snapshot, profile, {
            id: "ssh-configuration-weak",
            ruleId: "guest.ssh.weak-defaults",
            groupKey: "remote-access",
            title: "SSH daemon exposes high-risk defaults",
            summary: "The guest SSH configuration permits settings that weaken isolation or widen remote attack surface.",
            severity: profileAdjustedSeverity(profile, "high", "guest", ["guestHardening", "exposureSurface"]),
            confidence: "authoritative",
            certaintyReason: "The guest parsed the active SSH configuration files directly.",
            boundary: "guest",
            categories: ["guestHardening", "exposureSurface"],
            impactedSurfaces: ["sshd", "remote administration"],
            evidence: weakSettings.map(([key, value], index) =>
              evidence(snapshot, {
                id: `ssh-${index}`,
                label: key,
                kind: "config",
                value,
                source: "/etc/ssh/sshd_config",
                pathOrCommand: "read sshd_config and sshd_config.d/*.conf",
                interpretation: `${key} remains enabled.`,
                confidenceBasis: "Direct file parsing"
              })
            ),
            rationale: "Password login, root SSH, and X11 forwarding all expand attack and data leakage paths.",
            operatorImpact: "A network-exposed sshd becomes a much stronger crossover surface.",
            falsePositiveGuidance: "If SSH is intentionally exposed, keep the finding but treat it as accepted risk rather than a bug.",
            remediation: [
              {
                id: "manual-harden-ssh",
                title: "Harden SSH configuration",
                description: "Disable password login, root login, and X11 forwarding in sshd_config, then reload sshd.",
                requiresRoot: true,
                safeForAutomationLater: false,
                mode: "manual",
                commands: ["Set PasswordAuthentication no, PermitRootLogin no, X11Forwarding no, then reload sshd."]
              }
            ],
            riskFactors: [
              riskFactor("ssh", "Remote authentication", "SSH permits high-risk defaults.", "high", "guest")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false
          })
        }
      ];
    }
  },
  {
    run({ snapshot, profile }) {
      if (snapshot.security.sudoers.nopasswdEntries.length === 0) {
        return [];
      }

      return [
        {
          finding: createFinding(snapshot, profile, {
            id: "sudoers-nopasswd",
            ruleId: "guest.sudoers.nopasswd",
            groupKey: "privilege-paths",
            title: "Passwordless sudo entries were found",
            summary: "The guest sudoers configuration contains NOPASSWD rules.",
            severity: profileAdjustedSeverity(profile, "medium", "guest", ["guestHardening"]),
            confidence: "authoritative",
            certaintyReason: "The guest directly inspected sudoers files.",
            boundary: "guest",
            categories: ["guestHardening"],
            impactedSurfaces: ["local privilege escalation", "operator accounts"],
            evidence: snapshot.security.sudoers.nopasswdEntries.slice(0, 5).map((entry, index) =>
              evidence(snapshot, {
                id: `sudo-${index}`,
                label: "NOPASSWD entry",
                kind: "config",
                value: entry,
                source: "/etc/sudoers",
                pathOrCommand: "read /etc/sudoers and /etc/sudoers.d/*",
                interpretation: "Passwordless privilege escalation is configured.",
                confidenceBasis: "Direct file parsing"
              })
            ),
            rationale: "Passwordless sudo lowers the barrier from foothold to administrative execution inside the guest.",
            operatorImpact: "Compromised user sessions can escalate with less friction.",
            falsePositiveGuidance: "This may be acceptable on single-purpose automation guests, but it weakens compartmentalization.",
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
            riskFactors: [
              riskFactor("sudo", "Privilege escalation", "NOPASSWD sudo is configured.", "medium", "guest")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false
          })
        }
      ];
    }
  },
  {
    run({ snapshot, profile }) {
      const findings: CheckResult[] = [];

      if (snapshot.virtualization.sharedFolderMounts.length > 0) {
        findings.push({
          finding: createFinding(snapshot, profile, {
            id: "shared-folder-mounts-detected",
            ruleId: "guesthost.shared-folders.present",
            groupKey: "host-integration",
            title: "Shared folder mounts bridge guest and host storage",
            summary: "virtiofs or 9p shared mounts are present inside the guest.",
            severity: profileAdjustedSeverity(profile, "high", "guest-host interface", ["leakageRisk", "exposureSurface"]),
            confidence: "authoritative",
            certaintyReason: "The guest can directly read mounted filesystem types and mountpoints.",
            boundary: "guest-host interface",
            categories: ["leakageRisk", "exposureSurface"],
            impactedSurfaces: snapshot.virtualization.sharedFolderMounts.map((mount) => mount.mountPoint),
            evidence: snapshot.virtualization.sharedFolderMounts.map((mount, index) =>
              evidence(snapshot, {
                id: `shared-mount-${index}`,
                label: `${mount.fsType} mount`,
                kind: "mount",
                value: `${mount.source} -> ${mount.mountPoint}`,
                source: mount.collectedFrom,
                pathOrCommand: "cat /proc/mounts",
                interpretation: "Shared storage is directly available inside the guest.",
                confidenceBasis: "Direct mount table"
              })
            ),
            rationale: "Shared folders create an explicit crossover path between guest and host data domains.",
            operatorImpact: "Files can leak or be modified across the guest-host boundary with minimal friction.",
            falsePositiveGuidance: "Ignore only if the VM is not used for compartmentalization and the share is intentional.",
            remediation: [
              buildRemediationAction(
                "unmount-shared-folders",
                "Unmount shared folders",
                "Unmount all guest-visible shared folder mounts.",
                snapshot,
                true,
                true
              )
            ],
            riskFactors: [
              riskFactor("share", "Host file bridge", "Shared folders connect host and guest storage.", "high", "guest-host interface")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: true
          })
        });
      }

      if (snapshot.virtualization.qemuGuestAgent) {
        findings.push({
          finding: createFinding(snapshot, profile, {
            id: "qemu-guest-agent-present",
            ruleId: "guesthost.qemu-guest-agent.present",
            groupKey: "host-integration",
            title: "qemu-guest-agent is installed or reachable",
            summary: "The guest exposes a management surface to the host through qemu-guest-agent.",
            severity: profileAdjustedSeverity(profile, "medium", "guest-host interface", ["leakageRisk", "exposureSurface"]),
            confidence: "inferred",
            certaintyReason: "The guest can prove the channel exists, but not every host-side operation enabled over it.",
            boundary: "guest-host interface",
            categories: ["leakageRisk", "exposureSurface"],
            impactedSurfaces: snapshot.virtualization.guestAgentChannels,
            evidence: [
              evidence(snapshot, {
                id: "guest-agent-device",
                label: "Guest agent channel",
                kind: "virtio-channel",
                value: snapshot.virtualization.guestAgentChannels.join(", ") || "org.qemu.guest_agent.0",
                source: "/dev/virtio-ports",
                pathOrCommand: "ls /dev/virtio-ports",
                interpretation: "A qemu guest agent channel is visible in the guest.",
                confidenceBasis: "Direct device visibility; host-side capabilities still inferred"
              })
            ],
            rationale: "The guest agent improves manageability, but it also narrows the gap between host control and guest autonomy.",
            operatorImpact: "The host can often query or influence guest state more directly.",
            falsePositiveGuidance: "This is acceptable if the VM is managed operationally rather than isolated for compartmentalization.",
            remediation: [
              buildRemediationAction(
                "disable-qemu-guest-agent",
                "Disable qemu-guest-agent",
                "Disable guest agent integration unless host orchestration requires it.",
                snapshot,
                true,
                true
              )
            ],
            riskFactors: [
              riskFactor("agent", "Host orchestration channel", "qemu-guest-agent is present.", "medium", "guest-host interface")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: true,
            whyGuestCannotKnow: "The guest can see that the channel exists, but cannot certify which host workflows invoke it or how tightly the host constrains its use."
          })
        });
      }

      if (snapshot.virtualization.spiceVdagent) {
        findings.push({
          finding: createFinding(snapshot, profile, {
            id: "spice-vdagent-present",
            ruleId: "guesthost.spice-vdagent.present",
            groupKey: "host-integration",
            title: "SPICE vdagent introduces clipboard and desktop integration surfaces",
            summary: "SPICE guest integration software is active in the guest.",
            severity: profileAdjustedSeverity(profile, "medium", "guest-host interface", ["leakageRisk"]),
            confidence: "inferred",
            certaintyReason: "The guest can confirm the integration agent, but clipboard and file-transfer usage remain partially inferred.",
            boundary: "guest-host interface",
            categories: ["leakageRisk"],
            impactedSurfaces: ["clipboard", "desktop integration"],
            evidence: [
              evidence(snapshot, {
                id: "spice-vdagent",
                label: "SPICE agent",
                kind: "service",
                value: String(snapshot.virtualization.spiceVdagent),
                source: "systemctl/packages",
                pathOrCommand: "systemctl list-units and package inventory",
                interpretation: "SPICE integration tooling is installed or active.",
                confidenceBasis: "Direct service/package visibility; host-side clipboard use inferred"
              })
            ],
            rationale: "Clipboard and desktop integrations are convenient but expand data leakage paths across the guest boundary.",
            operatorImpact: "Users can unintentionally move sensitive data between host and guest environments.",
            falsePositiveGuidance: "Keep this as accepted risk only if GUI convenience is more important than strict isolation.",
            remediation: [
              buildRemediationAction(
                "disable-spice-vdagent",
                "Disable SPICE vdagent",
                "Disable desktop integration for higher-isolation profiles.",
                snapshot,
                true,
                true
              )
            ],
            riskFactors: [
              riskFactor("spice", "Clipboard and desktop bridge", "SPICE agent is present.", "medium", "guest-host interface")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: true,
            whyGuestCannotKnow: "The guest cannot prove whether the host currently allows clipboard sync or file transfer, only that the enabling agent exists."
          })
        });
      }

      if (snapshot.virtualization.vsockEnabled) {
        findings.push({
          finding: createFinding(snapshot, profile, {
            id: "vsock-enabled",
            ruleId: "guesthost.vsock.present",
            groupKey: "host-integration",
            title: "AF_VSOCK support is visible in the guest",
            summary: "The guest can likely communicate with host-adjacent services over AF_VSOCK.",
            severity: profileAdjustedSeverity(profile, "medium", "guest-host interface", ["leakageRisk", "exposureSurface"]),
            confidence: "inferred",
            certaintyReason: "The guest can prove AF_VSOCK support, but not every peer or service reachable over it.",
            boundary: "guest-host interface",
            categories: ["leakageRisk", "exposureSurface"],
            impactedSurfaces: ["AF_VSOCK"],
            evidence: [
              evidence(snapshot, {
                id: "vsock",
                label: "vsock enabled",
                kind: "device",
                value: String(snapshot.virtualization.vsockEnabled),
                source: "/dev/vsock",
                pathOrCommand: "ls /dev/vsock and inspect loaded modules",
                interpretation: "AF_VSOCK support is present.",
                confidenceBasis: "Direct device/module visibility; reachable peers inferred"
              })
            ],
            rationale: "AF_VSOCK adds a host-adjacent transport that bypasses some ordinary network assumptions.",
            operatorImpact: "Unexpected control paths can remain reachable even when ordinary networking is restricted.",
            falsePositiveGuidance: "This is acceptable for known guest tools that explicitly require vsock; otherwise review carefully.",
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
            riskFactors: [
              riskFactor("vsock", "Host-adjacent transport", "AF_VSOCK support is present.", "medium", "guest-host interface")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false,
            whyGuestCannotKnow: "The guest cannot enumerate every host or sibling service bound on AF_VSOCK without a cooperating peer."
          })
        });
      }

      return findings;
    }
  },
  {
    run({ snapshot, profile }) {
      const discoveryService = snapshot.services.find((service) => service.name === "avahi-daemon.service" && service.active);
      if (!discoveryService) {
        return [];
      }

      return [
        {
          finding: createFinding(snapshot, profile, {
            id: "avahi-discovery-enabled",
            ruleId: "guest.discovery.avahi-active",
            groupKey: "discovery-and-metadata",
            title: "mDNS discovery is active",
            summary: "avahi-daemon is active, which increases discovery and naming leakage on local networks.",
            severity: profileAdjustedSeverity(profile, "medium", "guest", ["exposureSurface", "leakageRisk"]),
            confidence: "authoritative",
            certaintyReason: "The guest directly observed the active avahi-daemon service.",
            boundary: "guest",
            categories: ["exposureSurface", "leakageRisk"],
            impactedSurfaces: ["mDNS", "service discovery"],
            evidence: [
              evidence(snapshot, {
                id: "avahi-service",
                label: "Active service",
                kind: "service",
                value: discoveryService.name,
                source: discoveryService.collectedFrom,
                pathOrCommand: "systemctl list-units",
                interpretation: "Local service discovery is active in the guest.",
                confidenceBasis: "Direct service state"
              })
            ],
            rationale: "Discovery protocols leak hostnames, service names, and make accidental reachability easier to exploit.",
            operatorImpact: "The VM becomes easier to locate and profile on adjacent networks.",
            falsePositiveGuidance: "This may be acceptable on a local desktop guest, but it is usually noise for compartmentalized systems.",
            remediation: [
              buildRemediationAction(
                "disable-avahi-daemon",
                "Disable avahi-daemon",
                "Disable mDNS and local service discovery inside the guest.",
                snapshot,
                true,
                true
              )
            ],
            riskFactors: [
              riskFactor("mdns", "Service discovery", "avahi-daemon is active.", "medium", "guest")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: true
          })
        }
      ];
    }
  },
  {
    run({ snapshot, profile }) {
      if ((snapshot.network.discoveryListeningSockets?.length ?? 0) > 0) {
        return [
          {
            finding: createFinding(snapshot, profile, {
              id: "discovery-sockets-present",
              ruleId: "guest.network.discovery-sockets",
              groupKey: "discovery-and-metadata",
              title: "Multicast/discovery listeners are active",
              summary: "The guest has multicast-bound service listeners that increase lateral visibility on local subnets.",
              severity: profileAdjustedSeverity(profile, "low", "guest", ["exposureSurface", "leakageRisk"]),
              confidence: "authoritative",
              certaintyReason: "The guest directly observed bound sockets to multicast destinations.",
              boundary: "guest-host interface",
              categories: ["exposureSurface", "leakageRisk"],
              impactedSurfaces: ["mDNS", "SSDP", "local discovery"],
              evidence: snapshot.network.discoveryListeningSockets.map((socket, index) =>
                evidence(snapshot, {
                  id: `discovery-${index}`,
                  label: `${socket.protocol} discovery listener`,
                  kind: "socket",
                  value: `${socket.protocol} ${socket.localAddress}`,
                  source: socket.collectedFrom,
                  pathOrCommand: "ss -H -lntup",
                  interpretation: `Discovery socket bound to ${socket.reachability}.`,
                  confidenceBasis: "Direct socket inspection"
                })
              ),
              rationale:
                "Discovery services like mDNS/SSDP help local discovery and also provide additional host/guest fingerprinting paths.",
              operatorImpact:
                "Discovery sockets do not always indicate open server services, but they do expand adjacent-network observability.",
              falsePositiveGuidance:
                "Suppress by disabling local discovery daemons only if service visibility and media casting are not required.",
              remediation: [],
              riskFactors: [
                riskFactor(
                  "discovery",
                  "Service discovery listeners",
                  "Multicast discovery surfaces are enabled.",
                  "low",
                  "guest-host interface"
                )
              ],
              relatedFindingIds: [],
              safeForAutomationLater: false
            })
          }
        ];
      }

      return [];
    }
  },
  {
    run({ snapshot, profile }) {
      if (snapshot.network.publicListeningSockets.length === 0) {
        return [];
      }

      const wildcardCount = snapshot.network.publicListeningSockets.filter((socket) => socket.bindScope === "wildcard").length;
      const severity = wildcardCount > 0 || snapshot.network.publicListeningSockets.length > 3 ? "high" : "medium";

      return [
        {
          finding: createFinding(snapshot, profile, {
            id: "public-listeners-present",
            ruleId: "guest.network.public-listeners",
            groupKey: "remote-access",
            title: "Guest services listen on non-loopback addresses",
            summary: "One or more sockets are bound beyond localhost.",
            severity: profileAdjustedSeverity(profile, severity, "guest", ["exposureSurface", "guestHardening"]),
            confidence: "authoritative",
            certaintyReason: "The guest directly observed listening sockets, bind addresses, and in some cases process names.",
            boundary: "guest",
            categories: ["exposureSurface", "guestHardening"],
            impactedSurfaces: snapshot.network.publicListeningSockets.map((socket) =>
              socket.process ? `${socket.process}:${socket.port ?? "?"}` : socket.localAddress
            ),
            evidence: snapshot.network.publicListeningSockets.slice(0, 12).map((socket, index) =>
              evidence(snapshot, {
                id: `listener-${index}`,
                label: socket.process ? `${socket.process} listener` : "Listening socket",
                kind: "socket",
                value: `${socket.protocol} ${socket.localAddress}${socket.pid ? ` pid=${socket.pid}` : ""}`,
                source: socket.collectedFrom,
                pathOrCommand: "ss -H -lntup",
                interpretation: `Socket is reachable as ${socket.reachability}.`,
                confidenceBasis: "Direct socket inspection"
              })
            ),
            rationale: "Services that bind beyond loopback can become reachable from the host or LAN depending on networking mode and firewall policy.",
            operatorImpact: "The guest's attack surface grows with every externally bound socket.",
            falsePositiveGuidance: "This can be acceptable for an intentionally exposed server guest, but it is usually a hardening regression for isolated desktops.",
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
            riskFactors: [
              riskFactor("listeners", "Externally bound sockets", `${snapshot.network.publicListeningSockets.length} non-loopback listeners were detected.`, severity, "guest")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false
          })
        }
      ];
    }
  },
  {
    run({ snapshot, profile }) {
      if (!snapshot.network.metadataRoutePresent) {
        return [];
      }

      return [
        {
          finding: createFinding(snapshot, profile, {
            id: "metadata-route-present",
            ruleId: "guesthost.network.metadata-route",
            groupKey: "discovery-and-metadata",
            title: "Cloud-style metadata route is present",
            summary: "The guest routing table references 169.254.169.254.",
            severity: profileAdjustedSeverity(profile, "high", "guest-host interface", ["exposureSurface", "leakageRisk"]),
            confidence: "inferred",
            certaintyReason: "The guest can prove the metadata route exists, but not what service actually answers it.",
            boundary: "guest-host interface",
            categories: ["exposureSurface", "leakageRisk"],
            impactedSurfaces: ["169.254.169.254"],
            evidence: snapshot.network.routes
              .filter((route) => route.raw.includes("169.254.169.254"))
              .map((route, index) =>
                evidence(snapshot, {
                  id: `metadata-${index}`,
                  label: "Metadata route",
                  kind: "route",
                  value: route.raw,
                  source: route.collectedFrom,
                  pathOrCommand: "ip route show",
                  interpretation: "A metadata-style endpoint is reachable from the guest.",
                  confidenceBasis: "Direct route table; responding endpoint inferred"
                })
              ),
            rationale: "Metadata endpoints are a common credential and environment leakage path.",
            operatorImpact: "Guest processes may be able to query instance metadata or host-supplied secrets.",
            falsePositiveGuidance: "If this VM intentionally runs in a cloud-style environment, treat the risk as policy-driven rather than accidental.",
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
            riskFactors: [
              riskFactor("metadata", "Metadata endpoint", "A metadata-style route exists.", "high", "guest-host interface")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false,
            whyGuestCannotKnow: "The guest can see the route, but cannot prove which platform component serves the endpoint or what authorization it enforces."
          })
        }
      ];
    }
  },
  {
    run({ snapshot, profile }) {
      if (snapshot.filePermissionIssues.length === 0) {
        return [];
      }

      return [
        {
          finding: createFinding(snapshot, profile, {
            id: "world-writable-sensitive-paths",
            ruleId: "guest.files.world-writable-sensitive",
            groupKey: "privilege-paths",
            title: "Sensitive paths include world-writable entries",
            summary: "World-writable files or directories were found in privileged paths.",
            severity: profileAdjustedSeverity(profile, "medium", "guest", ["guestHardening"]),
            confidence: "authoritative",
            certaintyReason: "The guest directly inspected filesystem permission bits.",
            boundary: "guest",
            categories: ["guestHardening"],
            impactedSurfaces: snapshot.filePermissionIssues.slice(0, 10).map((issue) => issue.path),
            evidence: snapshot.filePermissionIssues.slice(0, 10).map((issue, index) =>
              evidence(snapshot, {
                id: `perm-${index}`,
                label: "File permission issue",
                kind: "filesystem",
                value: `${issue.path} (${issue.mode})`,
                source: issue.collectedFrom,
                pathOrCommand: "stat during privileged path scan",
                interpretation: issue.reason,
                confidenceBasis: "Direct filesystem metadata"
              })
            ),
            rationale: "Weak file permissions can turn minor service compromise into persistence or privilege escalation.",
            operatorImpact: "Attackers can replace scripts, configs, or drop persistence more easily.",
            falsePositiveGuidance: "Some directories are intentionally writable, but privileged paths should require justification.",
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
            riskFactors: [
              riskFactor("filesystem", "Privileged path permissions", "World-writable entries exist in privileged paths.", "medium", "guest")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false
          })
        }
      ];
    }
  },
  {
    run({ snapshot, profile }) {
      const results: CheckResult[] = [];

      for (const vulnerability of snapshot.vulnerabilities) {
        results.push({
          finding: createFinding(snapshot, profile, {
            id: `advisory-${vulnerability.packageName}`,
            ruleId: "guest.packages.advisory-match",
            groupKey: "package-risk",
            title: `Installed package matches advisory: ${vulnerability.packageName}`,
            summary: vulnerability.summary,
            severity: vulnerability.severity,
            confidence: snapshot.advisoryBundle?.stale ? "inferred" : "authoritative",
            certaintyReason: snapshot.advisoryBundle?.stale
              ? "The package match is real, but the advisory bundle is stale so exploit relevance may be outdated."
              : "The package match was derived from the installed guest package list and current advisory bundle.",
            boundary: "guest",
            categories: ["guestHardening", "observabilityConfidence"],
            impactedSurfaces: [vulnerability.packageName],
            evidence: [
              evidence(snapshot, {
                id: "package",
                label: "Installed package",
                kind: "package",
                value: `${vulnerability.packageName} ${vulnerability.installedVersion ?? ""}`.trim(),
                source: snapshot.advisoryBundle?.source ?? "advisory-bundle",
                pathOrCommand: "guest package inventory matched against imported advisory bundle",
                interpretation: "The package is present and matched a known advisory record.",
                confidenceBasis: snapshot.advisoryBundle?.stale ? "Direct match with stale advisory bundle" : "Direct match with active advisory bundle"
              }),
              evidence(snapshot, {
                id: "bundle",
                label: "Advisory bundle",
                kind: "bundle",
                value: snapshot.advisoryBundle?.bundleId ?? "none",
                source: snapshot.advisoryBundle?.source ?? "advisory-bundle",
                pathOrCommand: "offline advisory bundle",
                interpretation: "Offline bundle used for vulnerability matching.",
                confidenceBasis: "Bundle metadata"
              })
            ],
            rationale: "Package-level advisories identify software that likely needs patching or removal inside the guest.",
            operatorImpact: "Known vulnerable packages can increase guest compromise risk or persistence durability.",
            falsePositiveGuidance: "Offline bundles can lag vendor backports; validate with the distro security tracker when patch precision matters.",
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
            riskFactors: [
              riskFactor("package", "Known software issue", vulnerability.packageName, vulnerability.severity, "guest")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false
          })
        });
      }

      if (snapshot.advisoryBundle?.stale) {
        results.push({
          finding: createFinding(snapshot, profile, {
            id: "advisory-bundle-stale",
            ruleId: "guest.advisory-bundle.stale",
            groupKey: "observability",
            title: "Offline advisory bundle is stale",
            summary: "Package risk evaluation is based on an outdated advisory bundle.",
            severity: "medium",
            confidence: "authoritative",
            certaintyReason: "Bundle metadata directly indicates that the imported advisory data is stale.",
            boundary: "guest",
            categories: ["observabilityConfidence"],
            impactedSurfaces: ["offline advisory bundle"],
            evidence: [
              evidence(snapshot, {
                id: "bundle-age",
                label: "Bundle generated at",
                kind: "bundle",
                value: snapshot.advisoryBundle.generatedAt,
                source: snapshot.advisoryBundle.source,
                pathOrCommand: "offline advisory bundle metadata",
                interpretation: "The advisory data is too old for strong confidence.",
                confidenceBasis: "Direct metadata"
              })
            ],
            rationale: "Stale advisory data undermines vulnerability accuracy and prioritization quality.",
            operatorImpact: "Package findings may be incomplete or outdated.",
            falsePositiveGuidance: "If the bundle is intentionally frozen for lab use, keep the finding but lower operational urgency.",
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
            riskFactors: [
              riskFactor("bundle", "Vulnerability telemetry freshness", "Offline advisory bundle is stale.", "medium", "guest")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false
          })
        });
      } else if (snapshot.advisoryBundle && !snapshot.advisoryBundle.verified) {
        results.push({
          finding: createFinding(snapshot, profile, {
            id: "advisory-bundle-unverified",
            ruleId: "guest.advisory-bundle.unverified",
            groupKey: "observability",
            title: "Offline advisory bundle is not signature-verified",
            summary: "The current advisory bundle is present but was not cryptographically verified against a trusted key.",
            severity: "low",
            confidence: "authoritative",
            certaintyReason: "Bundle metadata directly indicates verification status.",
            boundary: "guest",
            categories: ["observabilityConfidence"],
            impactedSurfaces: ["offline advisory bundle trust"],
            evidence: [
              evidence(snapshot, {
                id: "bundle-verified",
                label: "Bundle verified",
                kind: "bundle",
                value: String(snapshot.advisoryBundle.verified),
                source: snapshot.advisoryBundle.source,
                pathOrCommand: "offline advisory bundle metadata",
                interpretation: "Bundle authenticity could not be confirmed.",
                confidenceBasis: "Direct metadata"
              })
            ],
            rationale: "Unverified offline vulnerability data weakens trust in package risk conclusions.",
            operatorImpact: "Use package findings as guidance, not source-of-truth vulnerability attestations.",
            falsePositiveGuidance: "This is expected in development mode when no trusted signing keys are configured.",
            remediation: [],
            riskFactors: [
              riskFactor("bundle-trust", "Advisory trust", "Bundle is not signature-verified.", "low", "guest")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false
          })
        });
      }

      return results;
    }
  },
  {
    run({ snapshot, profile }) {
      const exposed = snapshot.network.publicListeningSockets.length > 0;
      const noDefaultDeny = !snapshot.security.firewall.defaultDenyInbound;
      const bridgeLikely = snapshot.network.bridgeLikely;

      if (!exposed || !noDefaultDeny || !bridgeLikely) {
        return [];
      }

      return [
        {
          finding: createFinding(snapshot, profile, {
            id: "combined-exposure-path",
            ruleId: "guest.attack-path.exposed-service-bridge",
            groupKey: "exposure-control",
            title: "Combined exposure path suggests services may be reachable beyond the host",
            summary:
              "The guest has non-loopback listeners, lacks a confirmed default-deny inbound firewall, and shows a private-gateway topology that may be reachability-facing.",
            severity: profileAdjustedSeverity(profile, "critical", "guest-host interface", ["exposureSurface", "leakageRisk"]),
            confidence: "inferred",
            certaintyReason:
              "Each signal is guest-visible, but the final reachability claim depends on host networking behavior the guest cannot directly certify.",
            boundary: "guest-host interface",
            categories: ["exposureSurface", "leakageRisk", "observabilityConfidence"],
            impactedSurfaces: ["network boundary", ...snapshot.network.publicListeningSockets.slice(0, 4).map((socket) => socket.localAddress)],
            evidence: [
              evidence(snapshot, {
                id: "gateway",
                label: "Default gateway type",
                kind: "route",
                value: snapshot.network.defaultGatewayType,
                source: "ip route show",
                pathOrCommand: "ip route show",
                interpretation: "Private gateway topology suggests potential LAN exposure; this is not proven from the guest alone.",
                confidenceBasis: "Direct route table with inferred host networking mode"
              }),
              evidence(snapshot, {
                id: "listener-count",
                label: "Public listener count",
                kind: "socket",
                value: String(snapshot.network.publicListeningSockets.length),
                source: "ss -H -lntup",
                pathOrCommand: "ss -H -lntup",
                interpretation: "Non-loopback listeners are present.",
                confidenceBasis: "Direct socket inspection"
              }),
              evidence(snapshot, {
                id: "firewall-policy",
                label: "Inbound policy",
                kind: "firewall",
                value: snapshot.security.firewall.inputPolicy,
                source: snapshot.security.firewall.source,
                pathOrCommand: snapshot.security.firewall.collectedFrom,
                interpretation: "Inbound default deny was not confirmed.",
                confidenceBasis: snapshot.security.firewall.inferenceQuality
              })
            ],
            rationale: "Exposure risk is highest when independently risky signals reinforce each other instead of standing alone.",
            operatorImpact: "A service accidentally exposed inside the guest may already be reachable from adjacent systems.",
            falsePositiveGuidance: "Treat this as a strong triage signal, not absolute proof of LAN reachability. The guest cannot inspect the host bridge or tap policy directly.",
            remediation: [
              {
                id: "manual-reduce-combined-exposure",
                title: "Reduce combined exposure path",
                description: "Tighten the guest firewall and move unnecessary services back to localhost-only binding.",
                requiresRoot: true,
                safeForAutomationLater: false,
                mode: "manual",
                commands: ["Set a default-deny inbound policy and restrict exposed services to loopback where possible."]
              }
            ],
            riskFactors: [
              riskFactor("combined", "Reinforcing network signals", "Listeners, firewall posture, and gateway type align to create stronger exposure risk.", "critical", "guest-host interface")
            ],
            relatedFindingIds: ["public-listeners-present", "guest-firewall-not-default-deny", "guest-firewall-missing"],
            safeForAutomationLater: false,
            whyGuestCannotKnow: "The guest cannot directly inspect libvirt NIC mode, host bridge membership, or host firewall rules, so final reachability remains inferred."
          })
        }
      ];
    }
  },
  {
    run({ snapshot, profile }) {
      return [
        {
          finding: createFinding(snapshot, profile, {
            id: "host-libvirt-xml-unverifiable",
            ruleId: "host.unverifiable.libvirt-launch",
            groupKey: "host-blind-spots",
            title: "Host libvirt and QEMU launch isolation cannot be verified from the guest",
            summary: "The guest cannot directly inspect libvirt XML, QEMU flags, or host-side tap and bridge policy.",
            severity: "info",
            confidence: "unverifiable",
            certaintyReason: "This is a deliberate trust-boundary limit, not a collection failure.",
            boundary: "host-unverifiable",
            categories: ["unverifiableHostControls", "observabilityConfidence"],
            impactedSurfaces: ["libvirt XML", "QEMU launch arguments"],
            evidence: [
              evidence(snapshot, {
                id: "visibility",
                label: "Visibility limit",
                kind: "trust-model",
                value: "Host launch configuration is not observable from inside the guest.",
                source: "trust-model",
                pathOrCommand: "guest-only design",
                interpretation: "Host launcher details are outside the guest trust boundary.",
                confidenceBasis: "Architectural limit"
              })
            ],
            rationale: "A guest-resident tool must not imply certainty about host-side isolation controls it cannot inspect.",
            operatorImpact: "Use this as a reminder that host attestation is still a separate problem.",
            falsePositiveGuidance: "Do not suppress this globally. It documents a real visibility limit.",
            remediation: [],
            riskFactors: [
              riskFactor("visibility", "Host launch configuration", "Host-side launch policy is outside guest visibility.", "info", "host-unverifiable")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false,
            whyGuestCannotKnow: "By design, strict guest-only telemetry cannot inspect host launch-time configuration."
          })
        },
        {
          finding: createFinding(snapshot, profile, {
            id: "host-storage-unverifiable",
            ruleId: "host.unverifiable.storage-and-dma",
            groupKey: "host-blind-spots",
            title: "Host snapshot storage and DMA posture cannot be certified",
            summary: "The guest cannot determine how disk images, snapshots, or IOMMU protections are configured on the host.",
            severity: "info",
            confidence: "unverifiable",
            certaintyReason: "Storage permissions and DMA isolation are host responsibilities outside guest visibility.",
            boundary: "host-unverifiable",
            categories: ["unverifiableHostControls", "observabilityConfidence"],
            impactedSurfaces: ["snapshot storage", "IOMMU/DMA policy"],
            evidence: [
              evidence(snapshot, {
                id: "storage-limit",
                label: "Visibility limit",
                kind: "trust-model",
                value: "Host storage permissions and DMA protections are outside guest visibility.",
                source: "trust-model",
                pathOrCommand: "guest-only design",
                interpretation: "These host controls cannot be certified from inside the VM.",
                confidenceBasis: "Architectural limit"
              })
            ],
            rationale: "These controls materially affect isolation but require host-side verification.",
            operatorImpact: "Guest analytics cannot replace host storage and hypervisor hygiene review.",
            falsePositiveGuidance: "This is an intentional blind-spot disclosure, not a false positive.",
            remediation: [],
            riskFactors: [
              riskFactor("host-storage", "Host storage policy", "Host image handling and DMA policy remain unverifiable.", "info", "host-unverifiable")
            ],
            relatedFindingIds: [],
            safeForAutomationLater: false,
            whyGuestCannotKnow: "The guest cannot read the host filesystem permissions, storage backend, or hardware DMA protections."
          })
        }
      ];
    }
  }
];

export function runChecks(snapshot: ScanSnapshot, profile: PolicyProfile): Finding[] {
  return checks
    .flatMap((check) => check.run({ snapshot, profile }).map((result) => result.finding))
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
}

export function buildFindingGroups(findings: Finding[], latestScanId?: string): FindingGroup[] {
  const grouped = new Map<string, Finding[]>();

  for (const finding of findings) {
    const list = grouped.get(finding.groupKey) ?? [];
    list.push(finding);
    grouped.set(finding.groupKey, list);
  }

  return [...grouped.entries()]
    .map(([groupKey, items]) => {
      const dominant = [...items].sort((left, right) => severityRank(right.severity) - severityRank(left.severity))[0];
      const confidence = items.reduce<ConfidenceLevel>((current, item) =>
        confidenceRank(item.confidence) > confidenceRank(current) ? item.confidence : current
      , "unverifiable");

      return {
        id: groupKey,
        title: dominant.title,
        summary:
          items.length === 1
            ? dominant.summary
            : `${items.length} related findings are grouped under ${dominant.title.toLowerCase()}.`,
        severity: dominant.severity,
        confidence,
        boundary: dominant.boundary,
        categories: [...new Set(items.flatMap((item) => item.categories))],
        findingIds: items.map((item) => item.id),
        count: items.length,
        impactedSurfaces: [...new Set(items.flatMap((item) => item.impactedSurfaces))].slice(0, 8),
        newInLatest: latestScanId ? items.some((item) => item.introducedInScan === latestScanId) : false
      };
    })
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
}
