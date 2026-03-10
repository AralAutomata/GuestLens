import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { getAdvisoryBundleStatus, matchVulnerabilities } from "@/lib/security/advisories";
import type {
  FilePermissionIssue,
  FirewallState,
  ListeningSocket,
  MountRecord,
  PackageRecord,
  ScanSnapshot,
  ServiceRecord,
  SshConfigState
} from "@/lib/types";

const COLLECTOR_VERSION = "0.1.0";

function safeRead(filePath: string): string | null {
  try {
    return readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function safeList(dirPath: string): string[] {
  try {
    return readdirSync(dirPath);
  } catch {
    return [];
  }
}

function commandExists(command: string): boolean {
  const pathEntries = (process.env.PATH ?? "").split(":");
  return pathEntries.some((entry) => existsSync(path.join(entry, command)));
}

function runCommand(command: string, args: string[] = []): string {
  try {
    return execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 4000
    }).trim();
  } catch {
    return "";
  }
}

function parseOsRelease(): { distro: string; version: string } {
  const raw = safeRead("/etc/os-release");
  if (!raw) {
    return { distro: "Unknown Linux", version: "unknown" };
  }

  const values = Object.fromEntries(
    raw
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [key, ...rest] = line.split("=");
        return [key, rest.join("=").replace(/^"/, "").replace(/"$/, "")];
      })
  );

  return {
    distro: values.PRETTY_NAME ?? values.NAME ?? "Unknown Linux",
    version: values.VERSION_ID ?? "unknown"
  };
}

function detectSecureBoot(): "enabled" | "disabled" | "not-exposed" | "unknown" {
  const efivarsDir = "/sys/firmware/efi/efivars";
  if (!existsSync(efivarsDir)) {
    return "not-exposed";
  }

  const entry = safeList(efivarsDir).find((item) => item.startsWith("SecureBoot-"));
  if (!entry) {
    return "unknown";
  }

  try {
    const raw = readFileSync(path.join(efivarsDir, entry));
    return raw.at(4) === 1 ? "enabled" : "disabled";
  } catch {
    return "unknown";
  }
}

function collectPackages(): PackageRecord[] {
  if (commandExists("dpkg-query")) {
    return runCommand("dpkg-query", ["-W", "-f=${Package}\t${Version}\n"])
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, version] = line.split("\t");
        return { name, version, manager: "dpkg" };
      });
  }

  if (commandExists("rpm")) {
    return runCommand("rpm", ["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, version] = line.split("\t");
        return { name, version, manager: "rpm" };
      });
  }

  if (commandExists("pacman")) {
    return runCommand("pacman", ["-Q"])
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, version] = line.split(" ");
        return { name, version, manager: "pacman" };
      });
  }

  return [];
}

function collectServices(): ServiceRecord[] {
  if (!commandExists("systemctl")) {
    return [];
  }

  const unitFiles = runCommand("systemctl", ["list-unit-files", "--type=service", "--no-legend", "--no-pager"]);
  const enabledMap = new Map<string, boolean>();
  for (const line of unitFiles.split("\n").filter(Boolean)) {
    const [name, state] = line.trim().split(/\s+/, 2);
    enabledMap.set(name, state === "enabled" || state === "static");
  }

  const activeUnits = new Set(
    runCommand("systemctl", ["list-units", "--type=service", "--state=active", "--no-legend", "--no-pager"])
      .split("\n")
      .filter(Boolean)
      .map((line) => line.trim().split(/\s+/, 2)[0])
  );

  return [...enabledMap.entries()]
    .map(([name, enabled]) => ({
      name,
      enabled,
      active: activeUnits.has(name)
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function collectMounts(): MountRecord[] {
  const raw = safeRead("/proc/mounts") ?? "";
  return raw
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [source, mountPoint, fsType, options] = line.split(" ");
      return {
        source,
        mountPoint,
        fsType,
        options: (options ?? "").split(",").filter(Boolean)
      };
    });
}

function parseListeningSockets(): ListeningSocket[] {
  if (!commandExists("ss")) {
    return [];
  }

  return runCommand("ss", ["-H", "-lntu"])
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const parts = line.trim().split(/\s+/);
      return {
        protocol: parts[0] ?? "unknown",
        localAddress: parts[4] ?? "unknown",
        raw: line
      };
    });
}

function parseDnsServers(): string[] {
  return (safeRead("/etc/resolv.conf") ?? "")
    .split("\n")
    .filter((line) => line.startsWith("nameserver "))
    .map((line) => line.replace("nameserver ", "").trim());
}

function collectFirewall(): FirewallState {
  if (commandExists("nft")) {
    const raw = runCommand("nft", ["list", "ruleset"]);
    return {
      backend: "nftables",
      rulesPresent: raw.length > 0,
      defaultDenyInbound: /hook input.*policy drop/s.test(raw) || /hook input.*policy reject/s.test(raw),
      defaultDenyOutbound: /hook output.*policy drop/s.test(raw) || /hook output.*policy reject/s.test(raw),
      rawSummary: raw.split("\n").slice(0, 20)
    };
  }

  if (commandExists("iptables-save")) {
    const raw = runCommand("iptables-save");
    return {
      backend: "iptables",
      rulesPresent: raw.length > 0,
      defaultDenyInbound: /:INPUT DROP/.test(raw),
      defaultDenyOutbound: /:OUTPUT DROP/.test(raw),
      rawSummary: raw.split("\n").slice(0, 20)
    };
  }

  return {
    backend: "none",
    rulesPresent: false,
    defaultDenyInbound: false,
    defaultDenyOutbound: false,
    rawSummary: []
  };
}

function parseConfigFiles(pathsToRead: string[]): Record<string, string> {
  const values: Record<string, string> = {};
  for (const filePath of pathsToRead) {
    const content = safeRead(filePath);
    if (!content) {
      continue;
    }

    for (const rawLine of content.split("\n")) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) {
        continue;
      }
      const [key, ...rest] = line.split(/\s+/);
      values[key.toLowerCase()] = rest.join(" ");
    }
  }

  return values;
}

function collectSsh(): SshConfigState {
  const base = "/etc/ssh";
  const configFiles = [path.join(base, "sshd_config")]
    .concat(
      safeList(path.join(base, "sshd_config.d"))
        .filter((entry) => entry.endsWith(".conf"))
        .map((entry) => path.join(base, "sshd_config.d", entry))
    )
    .filter((filePath) => existsSync(filePath));

  if (configFiles.length === 0) {
    return {
      installed: false
    };
  }

  const values = parseConfigFiles(configFiles);
  return {
    installed: true,
    permitRootLogin: values.permitrootlogin,
    passwordAuthentication: values.passwordauthentication,
    x11Forwarding: values.x11forwarding,
    pubkeyAuthentication: values.pubkeyauthentication
  };
}

function collectSudoers() {
  const candidates = ["/etc/sudoers"].concat(
    safeList("/etc/sudoers.d").map((entry) => path.join("/etc/sudoers.d", entry))
  );
  const nopasswdEntries: string[] = [];

  for (const filePath of candidates) {
    const content = safeRead(filePath);
    if (!content) {
      continue;
    }
    for (const line of content.split("\n")) {
      if (line.includes("NOPASSWD")) {
        nopasswdEntries.push(`${filePath}: ${line.trim()}`);
      }
    }
  }

  return { nopasswdEntries };
}

function collectFilePermissionIssues(): FilePermissionIssue[] {
  const targets = ["/etc", "/usr/local/bin", "/usr/local/sbin", "/var/lib"];
  const issues: FilePermissionIssue[] = [];

  function scan(currentPath: string, depth: number): void {
    if (depth > 2 || !existsSync(currentPath)) {
      return;
    }

    let stats;
    try {
      stats = lstatSync(currentPath);
    } catch {
      return;
    }

    const mode = stats.mode & 0o7777;
    if ((mode & 0o002) !== 0) {
      issues.push({
        path: currentPath,
        mode: mode.toString(8),
        reason: stats.isDirectory() ? "Directory is world-writable." : "File is world-writable."
      });
    }

    if (!stats.isDirectory()) {
      return;
    }

    try {
      for (const entry of readdirSync(currentPath, { withFileTypes: true })) {
        if (entry.name.startsWith(".")) {
          continue;
        }
        scan(path.join(currentPath, entry.name), depth + 1);
      }
    } catch {
      return;
    }
  }

  for (const target of targets) {
    scan(target, 0);
  }

  return issues;
}

function collectLsm() {
  const selinuxMode = existsSync("/sys/fs/selinux/enforce")
    ? safeRead("/sys/fs/selinux/enforce")?.trim() === "1"
      ? "enforcing"
      : "permissive"
    : "disabled";
  const appArmorRaw = safeRead("/sys/module/apparmor/parameters/enabled");
  const appArmorEnabled = appArmorRaw?.trim().toLowerCase() === "y";
  const appArmorProfilesLoaded = existsSync("/sys/kernel/security/apparmor/profiles");

  return {
    selinuxMode,
    appArmorEnabled,
    appArmorProfilesLoaded
  } as const;
}

function collectVirtualization(mounts: MountRecord[], services: ServiceRecord[], packages: PackageRecord[]) {
  const modules = (safeRead("/proc/modules") ?? "")
    .split("\n")
    .filter(Boolean)
    .map((line) => line.split(" ")[0]);
  const devicePaths = ["/dev/vsock", "/dev/hwrng", "/dev/virtio-ports/org.qemu.guest_agent.0"];

  const serviceNames = new Set(services.filter((service) => service.enabled || service.active).map((service) => service.name));
  const packageNames = new Set(packages.map((pkg) => pkg.name));

  return {
    qemuGuestAgent:
      serviceNames.has("qemu-guest-agent.service") ||
      packageNames.has("qemu-guest-agent") ||
      existsSync("/dev/virtio-ports/org.qemu.guest_agent.0"),
    spiceVdagent:
      serviceNames.has("spice-vdagentd.service") ||
      serviceNames.has("spice-vdagent.service") ||
      packageNames.has("spice-vdagent"),
    sharedFolderMounts: mounts.filter((mount) => mount.fsType === "virtiofs" || mount.fsType === "9p"),
    vsockEnabled: existsSync("/dev/vsock") || modules.includes("vsock") || modules.includes("vhost_vsock"),
    serialChannels: safeList("/dev/virtio-ports").map((item) => `/dev/virtio-ports/${item}`),
    passthroughHints: modules.filter((moduleName) => moduleName.startsWith("vfio") || moduleName.startsWith("pci_stub")),
    timeSyncHints: modules.filter((moduleName) => moduleName.includes("ptp") || moduleName.includes("hyperv")),
    rngDevicePresent: existsSync("/dev/hwrng"),
    ballooningEnabled: modules.includes("virtio_balloon")
  };
}

function collectNetwork() {
  const routes = commandExists("ip") ? runCommand("ip", ["route", "show"]).split("\n").filter(Boolean) : [];
  const neighbors = commandExists("ip") ? runCommand("ip", ["neigh", "show"]).split("\n").filter(Boolean) : [];
  const listeningSockets = parseListeningSockets();
  const publicListeningSockets = listeningSockets.filter(
    (socket) =>
      !socket.localAddress.startsWith("127.0.0.1") &&
      !socket.localAddress.startsWith("[::1]") &&
      !socket.localAddress.startsWith("::1")
  );

  return {
    hostname: os.hostname(),
    dnsServers: parseDnsServers(),
    routes,
    neighbors,
    listeningSockets,
    publicListeningSockets,
    metadataRoutePresent: routes.some((route) => route.includes("169.254.169.254"))
  };
}

export function collectSnapshot(): ScanSnapshot {
  const osRelease = parseOsRelease();
  const packages = collectPackages();
  const services = collectServices();
  const mounts = collectMounts();
  const advisoryBundle = getAdvisoryBundleStatus();

  return {
    id: crypto.randomUUID(),
    collectedAt: new Date().toISOString(),
    collectorVersion: COLLECTOR_VERSION,
    system: {
      distro: osRelease.distro,
      version: osRelease.version,
      kernelRelease: os.release(),
      kernelCommandLine: safeRead("/proc/cmdline")?.trim() ?? "",
      secureBootState: detectSecureBoot(),
      seccompAvailable: (safeRead("/proc/self/status") ?? "").includes("Seccomp:")
    },
    packages,
    services,
    mounts,
    network: collectNetwork(),
    filePermissionIssues: collectFilePermissionIssues(),
    security: {
      lsm: collectLsm(),
      firewall: collectFirewall(),
      ssh: collectSsh(),
      sudoers: collectSudoers()
    },
    virtualization: collectVirtualization(mounts, services, packages),
    advisoryBundle,
    vulnerabilities: matchVulnerabilities(packages)
  };
}

