import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { getAdvisoryBundleStatus, matchVulnerabilities } from "@/lib/security/advisories";
import type {
  DnsServerRecord,
  FilePermissionIssue,
  FirewallState,
  ListeningSocket,
  MountRecord,
  PackageRecord,
  RouteRecord,
  ScanSnapshot,
  ServiceRecord,
  SshConfigState,
  SshDirective
} from "@/lib/types";

const COLLECTOR_VERSION = "0.2.0";

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

interface CommandExecution {
  stdout: string;
  error: string | null;
}

function runCommandWithStatus(command: string, args: string[] = []): CommandExecution {
  try {
    return {
      stdout: execFileSync(command, args, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 5000
      }).trim(),
      error: null
    };
  } catch (error: unknown) {
    const commandError = error as
      | (Error & { stderr?: string | Buffer; message?: string })
      | { stderr?: string | Buffer; message?: string };
    const stderrText =
      typeof commandError.stderr === "string"
        ? commandError.stderr
        : commandError.stderr?.toString?.("utf8") ?? commandError.message ?? "";

    return {
      stdout: "",
      error: String(stderrText).trim()
    };
  }
}

function runCommand(command: string, args: string[] = []): string {
  return runCommandWithStatus(command, args).stdout;
}

function stripHostScope(address: string): string {
  const scopeIndex = address.indexOf("%");
  return scopeIndex === -1 ? address : address.slice(0, scopeIndex);
}

function isLoopbackHost(address: string): boolean {
  const host = stripHostScope(address).toLowerCase();

  if (!host || host === "localhost" || host === "::1" || host === "[::1]") {
    return true;
  }

  if (host.startsWith("127.")) {
    return true;
  }

  return host === "0:0:0:0:0:0:0:1";
}

function isMulticastHost(address: string): boolean {
  const host = stripHostScope(address).toLowerCase();
  if (!host) {
    return false;
  }

  return /^((ff[0-9a-f]{2}:)|224\.|239\.)/.test(host);
}

function isDiscoverySocket(socket: ListeningSocket): boolean {
  if (!socket.host || socket.port == null) {
    return false;
  }

  if (isMulticastHost(socket.host)) {
    return true;
  }

  if (socket.port === 5353 || socket.port === 5355 || socket.port === 1900 || socket.port === 3702) {
    return true;
  }

  return false;
}

function isPrivateGateway(gateway: string): boolean {
  return (
    gateway.startsWith("10.") ||
    gateway.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(gateway)
  );
}

function isPermissionError(error: string | null): boolean {
  if (!error) {
    return false;
  }

  return /operation not permitted|permission denied|must be root|not permitted/i.test(error);
}

function routeSubnetForGateway(gateway: string | undefined): string | undefined {
  if (!gateway) {
    return undefined;
  }

  const segments = gateway.split(".");
  if (segments.length !== 4) {
    return undefined;
  }

  return `${segments[0]}.${segments[1]}.${segments[2]}.0/24`;
}

function looksLikeLibvirtNatGateway(routes: RouteRecord[], defaultRoute?: RouteRecord): boolean {
  if (!defaultRoute?.via || !defaultRoute.device) {
    return false;
  }

  const gateway = defaultRoute.via;
  if (gateway === "192.168.122.1") {
    return true;
  }

  const subnet = routeSubnetForGateway(gateway);
  const hasSubnetRoute = subnet
    ? routes.some((route) => route.destination === subnet && route.device === defaultRoute.device && route.scope === "local-subnet")
    : false;
  const onVirbr = /^virbr\d+$/.test(defaultRoute.device);

  return onVirbr || (hasSubnetRoute && gateway.endsWith(".1"));
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

function collectPackages(observedAt: string): PackageRecord[] {
  if (commandExists("dpkg-query")) {
    return runCommand("dpkg-query", ["-W", "-f=${Package}\t${Version}\t${Architecture}\n"])
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, version, architecture] = line.split("\t");
        return {
          name,
          version,
          architecture,
          manager: "dpkg",
          observedAt,
          collectedFrom: "dpkg-query -W"
        };
      });
  }

  if (commandExists("rpm")) {
    return runCommand("rpm", ["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n"])
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, version, architecture, origin] = line.split("\t");
        return {
          name,
          version,
          architecture,
          origin,
          manager: "rpm",
          observedAt,
          collectedFrom: "rpm -qa"
        };
      });
  }

  if (commandExists("pacman")) {
    return runCommand("pacman", ["-Q"])
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, version] = line.split(" ");
        return {
          name,
          version,
          manager: "pacman",
          observedAt,
          collectedFrom: "pacman -Q"
        };
      });
  }

  return [];
}

function collectServices(observedAt: string): ServiceRecord[] {
  if (!commandExists("systemctl")) {
    return [];
  }

  const unitFiles = runCommand("systemctl", ["list-unit-files", "--type=service", "--no-legend", "--no-pager"]);
  const unitFileStates = new Map<string, string>();
  for (const line of unitFiles.split("\n").filter(Boolean)) {
    const [name, state] = line.trim().split(/\s+/, 2);
    unitFileStates.set(name, state ?? "unknown");
  }

  const activeStateByName = new Map<string, string>();
  const activeUnits = runCommand("systemctl", ["list-units", "--type=service", "--all", "--no-legend", "--no-pager"]);
  for (const line of activeUnits.split("\n").filter(Boolean)) {
    const [name, loadState, activeState] = line.trim().split(/\s+/, 3);
    if (!name) {
      continue;
    }
    activeStateByName.set(name, `${loadState ?? "unknown"}/${activeState ?? "unknown"}`);
  }

  return [...unitFileStates.entries()]
    .map(([name, unitFileState]) => {
      const activeState = activeStateByName.get(name) ?? "unknown/inactive";
      return {
        name,
        enabled: unitFileState === "enabled" || unitFileState === "static",
        active: activeState.includes("/active"),
        unitFileState,
        activeState,
        observedAt,
        collectedFrom: "systemctl"
      };
    })
    .sort((left, right) => left.name.localeCompare(right.name));
}

function collectMounts(observedAt: string): MountRecord[] {
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
        options: (options ?? "").split(",").filter(Boolean),
        observedAt,
        collectedFrom: "/proc/mounts"
      };
    });
}

function splitHostPort(value: string): { host: string; port: number | null; family: ListeningSocket["family"] } {
  if (value.startsWith("[") && value.includes("]:")) {
    const closing = value.lastIndexOf("]:");
    const host = value.slice(1, closing);
    const port = Number.parseInt(value.slice(closing + 2), 10);
    return { host, port: Number.isFinite(port) ? port : null, family: "ipv6" };
  }

  const lastColon = value.lastIndexOf(":");
  if (lastColon === -1) {
    return { host: value, port: null, family: "unknown" };
  }

  const host = value.slice(0, lastColon);
  const port = Number.parseInt(value.slice(lastColon + 1), 10);
  const family = host.includes(":") ? "ipv6" : "ipv4";
  return { host, port: Number.isFinite(port) ? port : null, family };
}

function bindScopeForHost(host: string): ListeningSocket["bindScope"] {
  if (isLoopbackHost(host)) {
    return "loopback";
  }
  if (host === "0.0.0.0" || host === "*" || host === "::" || host === "[::]") {
    return "wildcard";
  }
  return "specific-interface";
}

function parseProcessDetails(raw: string): { process?: string; pid?: number } {
  const processMatch = raw.match(/users:\(\("([^"]+)"/);
  const pidMatch = raw.match(/pid=(\d+)/);
  return {
    process: processMatch?.[1],
    pid: pidMatch ? Number.parseInt(pidMatch[1], 10) : undefined
  };
}

function parseListeningSockets(observedAt: string): ListeningSocket[] {
  if (!commandExists("ss")) {
    return [];
  }

  return runCommand("ss", ["-H", "-lntup"])
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const parts = line.trim().split(/\s+/);
      const localAddress = parts[4] ?? "unknown";
      const parsed = splitHostPort(localAddress);
      const host = stripHostScope(parsed.host);
      const bindScope = bindScopeForHost(host);
      return {
        protocol: parts[0] ?? "unknown",
        state: parts[1] ?? "unknown",
        family: parsed.family,
        host,
        port: parsed.port,
        localAddress,
        bindScope,
        reachability: bindScope === "loopback" ? "local-only" : bindScope === "wildcard" ? "wildcard" : "lan-or-host",
        raw: line,
        collectedFrom: "ss -H -lntup",
        parser: "ss",
        observedAt,
        ...parseProcessDetails(line)
      };
    });
}

function classifyAddress(address: string): DnsServerRecord["trustHint"] {
  if (address === "127.0.0.1" || address === "::1") {
    return "loopback";
  }
  if (address.startsWith("169.254.") || address.startsWith("fe80:")) {
    return "link-local";
  }
  if (
    address.startsWith("10.") ||
    address.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(address) ||
    address.startsWith("fd") ||
    address.startsWith("fc")
  ) {
    return "private";
  }
  if (address.length > 0) {
    return "public";
  }
  return "unknown";
}

function parseDnsServers(observedAt: string): DnsServerRecord[] {
  return (safeRead("/etc/resolv.conf") ?? "")
    .split("\n")
    .filter((line) => line.startsWith("nameserver "))
    .map((line) => line.replace("nameserver ", "").trim())
    .map((address) => ({
      address,
      source: "/etc/resolv.conf",
      observedAt,
      trustHint: classifyAddress(address)
    }));
}

function detectFirewallManagers(services: ServiceRecord[]): string[] {
  const managers: string[] = [];
  if (commandExists("ufw")) {
    managers.push("ufw");
  }
  if (services.some((service) => service.name === "firewalld.service" && service.active)) {
    managers.push("firewalld");
  }
  if (services.some((service) => service.name === "nftables.service" && service.active)) {
    managers.push("nftables");
  }
  return managers;
}

function policyFromRuleset(raw: string, hookName: "input" | "output"): string {
  const match = raw.match(new RegExp(`hook ${hookName}[^\\n]*policy (accept|drop|reject)`, "i"));
  return match?.[1]?.toLowerCase() ?? "unknown";
}

function collectFirewall(services: ServiceRecord[]): FirewallState {
  const activeManagers = detectFirewallManagers(services);

  if (commandExists("nft")) {
    const result = runCommandWithStatus("nft", ["list", "ruleset"]);
    const raw = result.stdout;

    if (isPermissionError(result.error)) {
      return {
        backend: "nftables",
        manager: activeManagers[0] ?? "nftables",
        rulesPresent: false,
        defaultDenyInbound: false,
        defaultDenyOutbound: false,
        inputPolicy: "unknown",
        outputPolicy: "unknown",
        inferenceQuality: "heuristic",
        inspectionAvailable: false,
        inspectionError: result.error ?? "permission denied while reading nft ruleset",
        activeManagers,
        rawSummary: [],
        source: "nft",
        collectedFrom: "nft list ruleset",
        parser: "regex-policy"
      };
    }

    const inputPolicy = policyFromRuleset(raw, "input");
    const outputPolicy = policyFromRuleset(raw, "output");
    return {
      backend: "nftables",
      manager: activeManagers[0] ?? "nftables",
      rulesPresent: raw.length > 0,
      defaultDenyInbound: inputPolicy === "drop" || inputPolicy === "reject",
      defaultDenyOutbound: outputPolicy === "drop" || outputPolicy === "reject",
      inputPolicy,
      outputPolicy,
      inferenceQuality: raw.length === 0 ? "none" : inputPolicy === "unknown" ? "heuristic" : "exact",
      inspectionAvailable: true,
      activeManagers,
      rawSummary: raw.split("\n").slice(0, 20),
      source: "nft",
      collectedFrom: "nft list ruleset",
      parser: "regex-policy"
    };
  }

  if (commandExists("iptables-save")) {
    const result = runCommandWithStatus("iptables-save");
    const raw = result.stdout;
    if (isPermissionError(result.error)) {
      return {
        backend: "iptables",
        manager: activeManagers[0] ?? "iptables",
        rulesPresent: false,
        defaultDenyInbound: false,
        defaultDenyOutbound: false,
        inputPolicy: "unknown",
        outputPolicy: "unknown",
        inferenceQuality: "heuristic",
        inspectionAvailable: false,
        inspectionError: result.error ?? "permission denied while reading iptables-save",
        activeManagers,
        rawSummary: [],
        source: "iptables-save",
        collectedFrom: "iptables-save",
        parser: "chain-policy"
      };
    }

    const inputPolicy = raw.match(/:INPUT (ACCEPT|DROP)/)?.[1]?.toLowerCase() ?? "unknown";
    const outputPolicy = raw.match(/:OUTPUT (ACCEPT|DROP)/)?.[1]?.toLowerCase() ?? "unknown";
    return {
      backend: "iptables",
      manager: activeManagers[0] ?? "iptables",
      rulesPresent: raw.length > 0,
      defaultDenyInbound: inputPolicy === "drop",
      defaultDenyOutbound: outputPolicy === "drop",
      inputPolicy,
      outputPolicy,
      inferenceQuality: raw.length === 0 ? "none" : inputPolicy === "unknown" ? "heuristic" : "exact",
      inspectionAvailable: true,
      activeManagers,
      rawSummary: raw.split("\n").slice(0, 20),
      source: "iptables-save",
      collectedFrom: "iptables-save",
      parser: "chain-policy"
    };
  }

  return {
    backend: "none",
    manager: activeManagers[0] ?? "none",
    rulesPresent: false,
    defaultDenyInbound: false,
    defaultDenyOutbound: false,
    inputPolicy: "unknown",
    outputPolicy: "unknown",
    inferenceQuality: "none",
    inspectionAvailable: false,
    inspectionError: "No supported firewall command (nft or iptables-save) available as this user.",
    activeManagers,
    rawSummary: [],
    source: "collector",
    collectedFrom: "none",
    parser: "none"
  };
}

function parseConfigFiles(pathsToRead: string[], observedAt: string): { values: Record<string, string>; directives: SshDirective[] } {
  const values: Record<string, string> = {};
  const directives: SshDirective[] = [];

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
      const normalizedKey = key.toLowerCase();
      const value = rest.join(" ");
      values[normalizedKey] = value;
      directives.push({
        key,
        value,
        source: filePath,
        observedAt,
        collectedFrom: "ssh-config"
      });
    }
  }

  return { values, directives };
}

function collectSsh(observedAt: string): SshConfigState {
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
      installed: false,
      directives: []
    };
  }

  const { values, directives } = parseConfigFiles(configFiles, observedAt);
  return {
    installed: true,
    directives,
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

function collectFilePermissionIssues(observedAt: string): FilePermissionIssue[] {
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
        reason: stats.isDirectory() ? "Directory is world-writable." : "File is world-writable.",
        observedAt,
        collectedFrom: "filesystem"
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
  const serialChannels = safeList("/dev/virtio-ports").map((item) => `/dev/virtio-ports/${item}`);
  const serviceNames = new Set(services.filter((service) => service.enabled || service.active).map((service) => service.name));
  const packageNames = new Set(packages.map((pkg) => pkg.name));

  return {
    qemuGuestAgent:
      serviceNames.has("qemu-guest-agent.service") ||
      packageNames.has("qemu-guest-agent") ||
      existsSync("/dev/virtio-ports/org.qemu.guest_agent.0"),
    guestAgentChannels: serialChannels.filter((item) => item.includes("guest_agent")),
    spiceVdagent:
      serviceNames.has("spice-vdagentd.service") ||
      serviceNames.has("spice-vdagent.service") ||
      packageNames.has("spice-vdagent"),
    clipboardIntegrationPossible:
      serviceNames.has("spice-vdagentd.service") ||
      serviceNames.has("spice-vdagent.service") ||
      packageNames.has("spice-vdagent"),
    sharedFolderMounts: mounts.filter((mount) => mount.fsType === "virtiofs" || mount.fsType === "9p"),
    vsockEnabled: existsSync("/dev/vsock") || modules.includes("vsock") || modules.includes("vhost_vsock"),
    serialChannels,
    passthroughHints: modules.filter((moduleName) => moduleName.startsWith("vfio") || moduleName.startsWith("pci_stub")),
    timeSyncHints: modules.filter((moduleName) => moduleName.includes("ptp") || moduleName.includes("hyperv")),
    sharedMemoryHints: modules.filter((moduleName) => moduleName.includes("ivshmem") || moduleName.includes("virtio_pmem")),
    rngDevicePresent: existsSync("/dev/hwrng"),
    ballooningEnabled: modules.includes("virtio_balloon")
  };
}

function parseRoutes(observedAt: string): RouteRecord[] {
  if (!commandExists("ip")) {
    return [];
  }

  return runCommand("ip", ["route", "show"])
    .split("\n")
    .filter(Boolean)
    .map((raw) => {
      const parts = raw.trim().split(/\s+/);
      const destination = parts[0] ?? "unknown";
      const viaIndex = parts.indexOf("via");
      const devIndex = parts.indexOf("dev");
      return {
        raw,
        destination,
        via: viaIndex !== -1 ? parts[viaIndex + 1] : undefined,
        device: devIndex !== -1 ? parts[devIndex + 1] : undefined,
        scope:
          destination === "default"
            ? "default"
            : destination.includes("169.254.")
              ? "link-local"
              : destination.includes("/24") || destination.includes("/16") || destination.includes("/64")
                ? "local-subnet"
                : "other",
        observedAt,
        collectedFrom: "ip route show"
      };
    });
}

function defaultGatewayType(routes: RouteRecord[]): "slirp" | "private-gateway" | "link-local" | "unknown" {
  const defaultRoute = routes.find((route) => route.destination === "default");
  const gateway = defaultRoute?.via ?? "";
  if (gateway === "10.0.2.2") {
    return "slirp";
  }
  if (gateway.startsWith("169.254.")) {
    return "link-local";
  }
  if (isPrivateGateway(gateway)) {
    return "private-gateway";
  }
  return "unknown";
}

function collectNetwork(observedAt: string) {
  const routes = parseRoutes(observedAt);
  const neighbors = commandExists("ip") ? runCommand("ip", ["neigh", "show"]).split("\n").filter(Boolean) : [];
  const listeningSockets = parseListeningSockets(observedAt);
  const discoveryListeningSockets = listeningSockets.filter(isDiscoverySocket);
  const publicListeningSockets = listeningSockets.filter(
    (socket) => socket.reachability !== "local-only" && !isDiscoverySocket(socket)
  );
  const multicastExposure = discoveryListeningSockets.length > 0;
  const gatewayType = defaultGatewayType(routes);
  const defaultRoute = routes.find((route) => route.destination === "default");
  const libvirtNatLikely = looksLikeLibvirtNatGateway(routes, defaultRoute);

  return {
    hostname: os.hostname(),
    dnsServers: parseDnsServers(observedAt),
    routes,
    neighbors,
    listeningSockets,
    publicListeningSockets,
    discoveryListeningSockets,
    metadataRoutePresent: routes.some((route) => route.raw.includes("169.254.169.254")),
    defaultGatewayType: gatewayType,
    bridgeLikely: gatewayType === "private-gateway" && !libvirtNatLikely,
    multicastExposure
  };
}

export function collectSnapshot(): ScanSnapshot {
  const collectedAt = new Date().toISOString();
  const osRelease = parseOsRelease();
  const packages = collectPackages(collectedAt);
  const services = collectServices(collectedAt);
  const mounts = collectMounts(collectedAt);
  const advisoryBundle = getAdvisoryBundleStatus();
  const vulnerabilities = matchVulnerabilities(packages).map((match) => ({
    ...match,
    installedVersion: packages.find((pkg) => pkg.name === match.packageName)?.version
  }));

  return {
    id: crypto.randomUUID(),
    collectedAt,
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
    network: collectNetwork(collectedAt),
    filePermissionIssues: collectFilePermissionIssues(collectedAt),
    security: {
      lsm: collectLsm(),
      firewall: collectFirewall(services),
      ssh: collectSsh(collectedAt),
      sudoers: collectSudoers()
    },
    virtualization: collectVirtualization(mounts, services, packages),
    advisoryBundle,
    vulnerabilities
  };
}
