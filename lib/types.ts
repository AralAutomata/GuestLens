export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type ConfidenceLevel = "authoritative" | "inferred" | "unverifiable";

export type AffectedBoundary = "guest" | "guest-host interface" | "host-unverifiable";

export type PolicyProfile = "balanced" | "high-isolation" | "paranoid-lab";

export type PostureCategory =
  | "guestHardening"
  | "exposureSurface"
  | "leakageRisk"
  | "observabilityConfidence"
  | "unverifiableHostControls";

export interface PolicyProfileDefinition {
  id: PolicyProfile;
  label: string;
  description: string;
  emphasis: string;
}

export interface EvidenceRecord {
  id: string;
  label: string;
  kind: string;
  value: string;
  source: string;
  collector: string;
  pathOrCommand: string;
  observedAt: string;
  interpretation: string;
  confidenceBasis: string;
}

export type Evidence = EvidenceRecord;

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
  architecture?: string;
  sourcePackage?: string;
  origin?: string;
  observedAt: string;
  collectedFrom: string;
}

export interface ServiceRecord {
  name: string;
  enabled: boolean;
  active: boolean;
  unitFileState?: string;
  activeState?: string;
  observedAt: string;
  collectedFrom: string;
}

export interface MountRecord {
  mountPoint: string;
  fsType: string;
  source: string;
  options: string[];
  observedAt: string;
  collectedFrom: string;
}

export interface ListeningSocket {
  protocol: string;
  family: "ipv4" | "ipv6" | "unknown";
  state?: string;
  host: string;
  port: number | null;
  localAddress: string;
  process?: string;
  pid?: number;
  bindScope: "loopback" | "wildcard" | "specific-interface";
  reachability: "local-only" | "lan-or-host" | "wildcard";
  raw: string;
  collectedFrom: string;
  parser: string;
  observedAt: string;
}

export interface RouteRecord {
  raw: string;
  destination: string;
  via?: string;
  device?: string;
  scope: "default" | "link-local" | "local-subnet" | "other";
  observedAt: string;
  collectedFrom: string;
}

export interface DnsServerRecord {
  address: string;
  source: string;
  observedAt: string;
  trustHint: "loopback" | "link-local" | "private" | "public" | "unknown";
}

export interface FilePermissionIssue {
  path: string;
  mode: string;
  reason: string;
  observedAt: string;
  collectedFrom: string;
}

export interface VulnerabilityMatch {
  packageName: string;
  installedVersion?: string;
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

export interface SshDirective {
  key: string;
  value: string;
  source: string;
  observedAt: string;
  collectedFrom: string;
}

export interface SshConfigState {
  installed: boolean;
  directives: SshDirective[];
  permitRootLogin?: string;
  passwordAuthentication?: string;
  x11Forwarding?: string;
  pubkeyAuthentication?: string;
}

export interface FirewallState {
  backend: string;
  manager: string;
  rulesPresent: boolean;
  defaultDenyInbound: boolean;
  defaultDenyOutbound: boolean;
  inputPolicy: string;
  outputPolicy: string;
  inferenceQuality: "exact" | "heuristic" | "none";
  activeManagers: string[];
  rawSummary: string[];
  source: string;
  collectedFrom: string;
  parser: string;
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
  guestAgentChannels: string[];
  spiceVdagent: boolean;
  clipboardIntegrationPossible: boolean;
  sharedFolderMounts: MountRecord[];
  vsockEnabled: boolean;
  serialChannels: string[];
  passthroughHints: string[];
  timeSyncHints: string[];
  sharedMemoryHints: string[];
  rngDevicePresent: boolean;
  ballooningEnabled: boolean;
}

export interface NetworkState {
  hostname: string;
  dnsServers: DnsServerRecord[];
  routes: RouteRecord[];
  neighbors: string[];
  listeningSockets: ListeningSocket[];
  publicListeningSockets: ListeningSocket[];
  metadataRoutePresent: boolean;
  defaultGatewayType: "slirp" | "private-gateway" | "link-local" | "unknown";
  bridgeLikely: boolean;
  multicastExposure: boolean;
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

export interface RiskFactor {
  id: string;
  label: string;
  detail: string;
  severity: Severity;
  boundary: AffectedBoundary;
}

export interface Finding {
  id: string;
  ruleId: string;
  groupKey: string;
  title: string;
  summary: string;
  severity: Severity;
  confidence: ConfidenceLevel;
  certaintyReason: string;
  boundary: AffectedBoundary;
  categories: PostureCategory[];
  profile: PolicyProfile;
  impactedSurfaces: string[];
  evidence: EvidenceRecord[];
  rationale: string;
  operatorImpact: string;
  falsePositiveGuidance: string;
  whyGuestCannotKnow?: string;
  remediation: RemediationAction[];
  riskFactors: RiskFactor[];
  relatedFindingIds: string[];
  safeForAutomationLater: boolean;
  createdAt: string;
  introducedInScan?: string;
}

export interface CheckResult {
  finding: Finding;
}

export interface FindingGroup {
  id: string;
  title: string;
  summary: string;
  severity: Severity;
  confidence: ConfidenceLevel;
  boundary: AffectedBoundary;
  categories: PostureCategory[];
  findingIds: string[];
  count: number;
  impactedSurfaces: string[];
  newInLatest: boolean;
}

export interface PostureScore {
  category: PostureCategory;
  title: string;
  score: number;
  summary: string;
  driverFindingIds: string[];
}

export interface PostureSummary {
  generatedAt: string;
  profile: PolicyProfile;
  scores: PostureScore[];
  overallScore: number;
  trustStatement: string;
  topPriorities: string[];
  deltaHeadline?: string;
}

export interface ScanDelta {
  fromScanId: string | null;
  toScanId: string;
  newFindingIds: string[];
  resolvedFindingIds: string[];
  changedFindingIds: string[];
  severityUpgrades: string[];
  confidenceDowngrades: string[];
  unchangedCount: number;
  summary: {
    newCount: number;
    resolvedCount: number;
    changedCount: number;
    severityUpgradeCount: number;
    confidenceDowngradeCount: number;
  };
}

export interface StoredScan {
  scanId: string;
  profile: PolicyProfile;
  snapshot: ScanSnapshot;
  findings: Finding[];
  groups: FindingGroup[];
  posture: PostureSummary;
  delta: ScanDelta | null;
}
