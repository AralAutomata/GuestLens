import { analyzeSnapshot } from "@/lib/security/analyzer";
import { buildFindingGroups } from "@/lib/security/checks";
import { getActiveProfile, getLatestScan, getScanById, getScanHistory, getStoredDelta, saveScan, setActiveProfile } from "@/lib/security/database";
import { buildScanDelta } from "@/lib/security/delta";
import { requestGuestScan } from "@/lib/security/collector-client";
import { POLICY_PROFILES } from "@/lib/security/profiles";
import type { PolicyProfile, ScanDelta, StoredScan } from "@/lib/types";

function enrichFindings(previous: StoredScan | null, current: StoredScan): StoredScan {
  const previousById = new Map(previous?.findings.map((finding) => [finding.id, finding]) ?? []);
  const delta = buildScanDelta(previous, current);
  const findings = current.findings.map((finding) => ({
    ...finding,
    introducedInScan: previousById.get(finding.id)?.introducedInScan ?? (delta.newFindingIds.includes(finding.id) ? current.scanId : current.scanId)
  }));
  const groups = buildFindingGroups(findings, current.scanId);

  return {
    ...current,
    findings,
    groups,
    posture: {
      ...current.posture,
      deltaHeadline:
        delta.fromScanId === null
          ? "Initial baseline captured."
          : `${delta.summary.newCount} new, ${delta.summary.resolvedCount} resolved, ${delta.summary.changedCount} changed since the previous scan.`
    },
    delta
  };
}

export async function runFullScan(): Promise<StoredScan> {
  const snapshot = await requestGuestScan();
  const activeProfile = getActiveProfile();
  const previous = getLatestScan();
  const analyzed = analyzeSnapshot(snapshot, activeProfile);
  const stored = enrichFindings(previous, analyzed);
  saveScan(stored);
  return stored;
}

export function getLatestStoredScan(): StoredScan | null {
  return getLatestScan();
}

export function getStoredScan(scanId: string): StoredScan | null {
  return getScanById(scanId);
}

export function getStoredHistory() {
  return getScanHistory();
}

export function getStoredDiff(fromScanId?: string | null, toScanId?: string | null): ScanDelta | null {
  const toScan = toScanId ? getScanById(toScanId) : getLatestScan();
  if (!toScan) {
    return null;
  }

  if (!fromScanId || fromScanId === toScan.delta?.fromScanId) {
    return getStoredDelta(toScan.scanId) ?? toScan.delta;
  }

  const fromScan = getScanById(fromScanId);
  if (!fromScan) {
    return null;
  }

  return buildScanDelta(fromScan, toScan);
}

export function getProfileState(): { activeProfile: PolicyProfile; profiles: typeof POLICY_PROFILES } {
  return {
    activeProfile: getActiveProfile(),
    profiles: POLICY_PROFILES
  };
}

export function updateActiveProfile(profile: PolicyProfile): { activeProfile: PolicyProfile; profiles: typeof POLICY_PROFILES } {
  setActiveProfile(profile);
  return getProfileState();
}

export function exportSanitizedScan(scanId?: string | null) {
  const stored = scanId ? getScanById(scanId) : getLatestScan();
  if (!stored) {
    return null;
  }

  return {
    product: "InsideJobVM",
    exportedAt: new Date().toISOString(),
    scanId: stored.scanId,
    profile: stored.profile,
    collectedAt: stored.snapshot.collectedAt,
    system: {
      distro: stored.snapshot.system.distro,
      version: stored.snapshot.system.version,
      kernelRelease: stored.snapshot.system.kernelRelease
    },
    posture: stored.posture,
    delta: stored.delta,
    findings: stored.findings.map((finding) => ({
      id: finding.id,
      ruleId: finding.ruleId,
      title: finding.title,
      summary: finding.summary,
      severity: finding.severity,
      confidence: finding.confidence,
      certaintyReason: finding.certaintyReason,
      boundary: finding.boundary,
      impactedSurfaces: finding.impactedSurfaces,
      rationale: finding.rationale,
      operatorImpact: finding.operatorImpact,
      falsePositiveGuidance: finding.falsePositiveGuidance,
      remediation: finding.remediation,
      evidence: finding.evidence.map((item) => ({
        label: item.label,
        value: item.value,
        source: item.source,
        pathOrCommand: item.pathOrCommand,
        interpretation: item.interpretation
      }))
    }))
  };
}
