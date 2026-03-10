export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type ConfidenceLevel = "authoritative" | "inferred" | "unverifiable";

export type AffectedBoundary = "guest" | "guest-host interface" | "host-unverifiable";

export type PostureCategory =
  | "guestHardening"
  | "exposureSurface"
  | "leakageRisk"
  | "remediationReadiness"
  | "unverifiableHostControls";

export interface Evidence {
  id: string;
  label: string;
  detail: string;
  source: string;
}

export interface RemediationAction {
  id: string;
  title: string;
  description: string;
  requiresRoot: boolean;
  safeForAutomationLater: boolean;
  mode: "manual" | "command";
  commands: string[];
}

export interface ExposureSurface {
  kind: string;
  label: string;
  detail: string;
  confidence: ConfidenceLevel;
}

export interface PackageRecord {
  name: string;
  version: string;
  manager: string;
}

export interface ServiceRecord {
  name: string;
  enabled: boolean;
  active: boolean;
}

export interface MountRecord {
  mountPoint: string;
  fsType: string;
  source: string;
  options: string[];
}

export interface ListeningSocket {
  protocol: string;
  localAddress: string;
  process?: string;
  raw: string;
}

export interface FilePermissionIssue {
  path: string;
  mode: string;
  reason: string;
}

export interface VulnerabilityMatch {
  packageName: string;
  summary: string;
  severity: Severity;
  cves: string[];
  source: string;
}

export interface AdvisoryBundleStatus {
  bundleId: string;
  generatedAt: string;
  expiresAt?: string;
  verified: boolean;
  stale: boolean;
  source: string;
  sha256: string;
}

export interface SshConfigState {
  installed: boolean;
  permitRootLogin?: string;
  passwordAuthentication?: string;
  x11Forwarding?: string;
  pubkeyAuthentication?: string;
}

export interface FirewallState {
  backend: string;
  rulesPresent: boolean;
  defaultDenyInbound: boolean;
  defaultDenyOutbound: boolean;
  rawSummary: string[];
}

export interface LsmState {
  selinuxMode: "enforcing" | "permissive" | "disabled" | "unknown";
  appArmorEnabled: boolean;
  appArmorProfilesLoaded: boolean;
}

export interface SudoersState {
  nopasswdEntries: string[];
}

export interface VirtualizationSurfaceState {
  qemuGuestAgent: boolean;
  spiceVdagent: boolean;
  sharedFolderMounts: MountRecord[];
  vsockEnabled: boolean;
  serialChannels: string[];
  passthroughHints: string[];
  timeSyncHints: string[];
  rngDevicePresent: boolean;
  ballooningEnabled: boolean;
}

export interface NetworkState {
  hostname: string;
  dnsServers: string[];
  routes: string[];
  neighbors: string[];
  listeningSockets: ListeningSocket[];
  publicListeningSockets: ListeningSocket[];
  metadataRoutePresent: boolean;
}

export interface SystemState {
  distro: string;
  version: string;
  kernelRelease: string;
  kernelCommandLine: string;
  secureBootState: "enabled" | "disabled" | "not-exposed" | "unknown";
  seccompAvailable: boolean;
}

export interface ScanSnapshot {
  id: string;
  collectedAt: string;
  collectorVersion: string;
  system: SystemState;
  packages: PackageRecord[];
  services: ServiceRecord[];
  mounts: MountRecord[];
  network: NetworkState;
  filePermissionIssues: FilePermissionIssue[];
  security: {
    lsm: LsmState;
    firewall: FirewallState;
    ssh: SshConfigState;
    sudoers: SudoersState;
  };
  virtualization: VirtualizationSurfaceState;
  advisoryBundle: AdvisoryBundleStatus | null;
  vulnerabilities: VulnerabilityMatch[];
}

export interface Finding {
  id: string;
  title: string;
  summary: string;
  severity: Severity;
  confidence: ConfidenceLevel;
  boundary: AffectedBoundary;
  categories: PostureCategory[];
  evidence: Evidence[];
  rationale: string;
  remediation: RemediationAction[];
  safeForAutomationLater: boolean;
  createdAt: string;
}

export interface PostureScore {
  category: PostureCategory;
  title: string;
  score: number;
  summary: string;
}

export interface PostureSummary {
  generatedAt: string;
  scores: PostureScore[];
  overallScore: number;
  trustStatement: string;
}

export interface StoredScan {
  scanId: string;
  snapshot: ScanSnapshot;
  findings: Finding[];
  posture: PostureSummary;
}
