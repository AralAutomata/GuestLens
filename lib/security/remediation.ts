import { existsSync } from "node:fs";
import path from "node:path";

import type { RemediationAction, ScanSnapshot } from "@/lib/types";

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
