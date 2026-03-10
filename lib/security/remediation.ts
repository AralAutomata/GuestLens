import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

import type { Evidence, Finding, RemediationAction, RemediationResult, ScanSnapshot } from "@/lib/types";

interface CommandPlan {
  argv: string[];
  description: string;
}

function commandExists(command: string): boolean {
  return (process.env.PATH ?? "").split(":").some((entry) => existsSync(path.join(entry, command)));
}

function hasService(snapshot: ScanSnapshot, name: string): boolean {
  return snapshot.services.some((service) => service.name === name);
}

function buildCommandPlan(actionId: string, snapshot: ScanSnapshot): CommandPlan[] {
  if (actionId === "disable-qemu-guest-agent" && hasService(snapshot, "qemu-guest-agent.service")) {
    return [
      {
        argv: ["systemctl", "disable", "--now", "qemu-guest-agent.service"],
        description: "Disable qemu-guest-agent."
      }
    ];
  }

  if (actionId === "disable-spice-vdagent") {
    const serviceName = hasService(snapshot, "spice-vdagentd.service")
      ? "spice-vdagentd.service"
      : hasService(snapshot, "spice-vdagent.service")
        ? "spice-vdagent.service"
        : null;
    if (serviceName) {
      return [
        {
          argv: ["systemctl", "disable", "--now", serviceName],
          description: "Disable SPICE vdagent."
        }
      ];
    }
  }

  if (actionId === "disable-avahi-daemon" && hasService(snapshot, "avahi-daemon.service")) {
    return [
      {
        argv: ["systemctl", "disable", "--now", "avahi-daemon.service"],
        description: "Disable avahi-daemon."
      }
    ];
  }

  if (actionId === "unmount-shared-folders") {
    return snapshot.virtualization.sharedFolderMounts.map((mount) => ({
      argv: ["umount", mount.mountPoint],
      description: `Unmount ${mount.mountPoint}.`
    }));
  }

  if (actionId === "enable-firewall") {
    if (commandExists("ufw")) {
      return [
        { argv: ["ufw", "--force", "default", "deny", "incoming"], description: "Default-deny inbound with ufw." },
        { argv: ["ufw", "--force", "enable"], description: "Enable ufw." }
      ];
    }
    if (hasService(snapshot, "nftables.service")) {
      return [
        {
          argv: ["systemctl", "enable", "--now", "nftables.service"],
          description: "Enable nftables service."
        }
      ];
    }
    if (hasService(snapshot, "firewalld.service")) {
      return [
        {
          argv: ["systemctl", "enable", "--now", "firewalld.service"],
          description: "Enable firewalld service."
        }
      ];
    }
  }

  return [];
}

export function buildRemediationAction(
  actionId: string,
  title: string,
  description: string,
  snapshot: ScanSnapshot,
  requiresRoot = true,
  safeForAutomationLater = false
): RemediationAction {
  const commands = buildCommandPlan(actionId, snapshot);
  return {
    id: actionId,
    title,
    description,
    requiresRoot,
    safeForAutomationLater,
    mode: commands.length > 0 ? "command" : "manual",
    commands: commands.map((command) => command.argv.join(" "))
  };
}

export function executeRemediation(action: RemediationAction, snapshot: ScanSnapshot, finding: Finding): RemediationResult {
  const beforeEvidence = finding.evidence;
  const plan = buildCommandPlan(action.id, snapshot);
  if (plan.length === 0) {
    return {
      actionId: action.id,
      executed: false,
      success: false,
      output: ["This remediation has no executable command plan on the current guest."],
      beforeEvidence,
      afterEvidence: beforeEvidence
    };
  }

  if (action.requiresRoot && process.getuid?.() !== 0) {
    return {
      actionId: action.id,
      executed: false,
      success: false,
      output: ["Root privileges are required. Re-run the application with an explicit privileged helper."],
      beforeEvidence,
      afterEvidence: beforeEvidence
    };
  }

  const output: string[] = [];
  for (const command of plan) {
    try {
      const [, ...args] = command.argv;
      const stdout = execFileSync(command.argv[0], args, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 10_000
      }).trim();
      output.push(`${command.description}${stdout ? ` ${stdout}` : ""}`.trim());
    } catch (error) {
      output.push(`${command.description} Failed: ${error instanceof Error ? error.message : "unknown error"}`);
      return {
        actionId: action.id,
        executed: true,
        success: false,
        output,
        beforeEvidence,
        afterEvidence: beforeEvidence
      };
    }
  }

  const afterEvidence: Evidence[] = [
    {
      id: `${action.id}-executed`,
      label: "Remediation executed",
      detail: "A follow-up scan is required to confirm the post-change state.",
      source: "remediation-helper"
    }
  ];

  return {
    actionId: action.id,
    executed: true,
    success: true,
    output,
    beforeEvidence,
    afterEvidence
  };
}

