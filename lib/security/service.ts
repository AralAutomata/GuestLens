import { analyzeSnapshot } from "@/lib/security/analyzer";
import { buildFindingGroups } from "@/lib/security/checks";
import {
  deleteSuppression,
  getActiveProfile,
  getLatestScan,
  getScanById,
  getScanHistory,
  getStoredDelta,
  listSuppressions,
  saveScan,
  saveSuppression,
  setActiveProfile
} from "@/lib/security/database";
import { buildScanDelta } from "@/lib/security/delta";
import { requestGuestScan } from "@/lib/security/collector-client";
import { POLICY_PROFILES } from "@/lib/security/profiles";
import { HOSTGUARD_SCHEMA_VERSION } from "@/lib/types";
import type { Finding, PolicyProfile, ScanDelta, StoredScan, SuppressionRecord } from "@/lib/types";

function suppressionForFinding(finding: Finding, suppressions: SuppressionRecord[]): SuppressionRecord | null {
  const now = Date.now();
  return (
    suppressions.find((suppression) => {
      if (suppression.expiresAt && Date.parse(suppression.expiresAt) <= now) {
        return false;
      }
      return suppression.scope === "rule"
        ? suppression.matchValue === finding.ruleId
        : suppression.matchValue === finding.fingerprint;
    }) ?? null
  );
}

function annotateSuppressions(stored: StoredScan | null): StoredScan | null {
  if (!stored) {
    return null;
  }

  const suppressions = listSuppressions();
  const findings = stored.findings.map((finding) => {
    const suppression = suppressionForFinding(finding, suppressions);
    return {
      ...finding,
      suppressed: Boolean(suppression),
      suppression
    };
  });

  const groups = buildFindingGroups(findings, stored.scanId);
  const delta = stored.delta
    ? {
        ...stored.delta,
        suppressedFindingIds: findings.filter((finding) => finding.suppressed).map((finding) => finding.id),
        summary: {
          ...stored.delta.summary,
          suppressedCount: findings.filter((finding) => finding.suppressed).length
        }
      }
    : null;

  return {
    ...stored,
    findings,
    groups,
    posture: {
      ...stored.posture,
      deltaHeadline:
        delta?.fromScanId === null
          ? delta.summary.suppressedCount > 0
            ? `Initial baseline captured. ${delta.summary.suppressedCount} suppressed.`
            : "Initial baseline captured."
          : delta
            ? `${delta.summary.newCount} new, ${delta.summary.resolvedCount} resolved, ${delta.summary.changedCount} changed since the previous scan.${delta.summary.suppressedCount > 0 ? ` ${delta.summary.suppressedCount} suppressed.` : ""}`
            : stored.posture.deltaHeadline
    },
    delta
  };
}

function enrichFindings(previous: StoredScan | null, current: StoredScan): StoredScan {
  const previousById = new Map(previous?.findings.map((finding) => [finding.id, finding]) ?? []);
  const findings = current.findings.map((finding) => ({
    ...finding,
    introducedInScan: previousById.get(finding.id)?.introducedInScan ?? current.scanId
  }));
  const groups = buildFindingGroups(findings, current.scanId);
  const stored = {
    ...current,
    findings,
    groups
  };
  const delta = buildScanDelta(previous, stored);

  return {
    ...stored,
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
  const previous = annotateSuppressions(getLatestScan());
  const analyzed = analyzeSnapshot(snapshot, activeProfile);
  const stored = annotateSuppressions(enrichFindings(previous, analyzed));
  if (!stored) {
    throw new Error("failed to store scan");
  }
  saveScan(stored);
  return stored;
}

export function getLatestStoredScan(): StoredScan | null {
  return annotateSuppressions(getLatestScan());
}

export function getStoredScan(scanId: string): StoredScan | null {
  return annotateSuppressions(getScanById(scanId));
}

export function getStoredHistory() {
  return getScanHistory();
}

export function getStoredDiff(fromScanId?: string | null, toScanId?: string | null): ScanDelta | null {
  const toScan = annotateSuppressions(toScanId ? getScanById(toScanId) : getLatestScan());
  if (!toScan) {
    return null;
  }

  if (!fromScanId || fromScanId === toScan.delta?.fromScanId) {
    return toScan.delta ?? getStoredDelta(toScan.scanId);
  }

  const fromScan = annotateSuppressions(getScanById(fromScanId));
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

export function exportSanitizedScan(scanId?: string | null, includeSuppressed = true) {
  const stored = annotateSuppressions(scanId ? getScanById(scanId) : getLatestScan());
  if (!stored) {
    return null;
  }

  const findings = includeSuppressed ? stored.findings : stored.findings.filter((finding) => !finding.suppressed);

  return {
    schemaVersion: HOSTGUARD_SCHEMA_VERSION,
    product: "HostGuard Linux",
    exportedAt: new Date().toISOString(),
    scanId: stored.scanId,
    profile: stored.profile,
    collectedAt: stored.snapshot.collectedAt,
    scope: "Guest-visible VM posture only",
    omittedData: [
      "Host firewall policy",
      "libvirt XML and launch flags",
      "hypervisor confinement labels",
      "host storage and snapshot controls"
    ],
    system: {
      distro: stored.snapshot.system.distro,
      version: stored.snapshot.system.version,
      kernelRelease: stored.snapshot.system.kernelRelease
    },
    environment: stored.snapshot.environment,
    advisoryBundle: stored.snapshot.advisoryBundle,
    posture: stored.posture,
    delta: stored.delta,
    findings: findings.map((finding) => ({
      id: finding.id,
      ruleId: finding.ruleId,
      title: finding.title,
      summary: finding.summary,
      severity: finding.severity,
      confidence: finding.confidence,
      certaintyReason: finding.certaintyReason,
      boundary: finding.boundary,
      fingerprint: finding.fingerprint,
      subcategory: finding.subcategory,
      impactedSurfaces: finding.impactedSurfaces,
      rationale: finding.rationale,
      operatorImpact: finding.operatorImpact,
      falsePositiveGuidance: finding.falsePositiveGuidance,
      remediationPreconditions: finding.remediationPreconditions,
      suppressed: finding.suppressed ?? false,
      suppression: finding.suppression,
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

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function exportHtmlReport(scanId?: string | null, includeSuppressed = true): string | null {
  const exported = exportSanitizedScan(scanId, includeSuppressed);
  if (!exported) {
    return null;
  }

  const findingRows = exported.findings
    .map(
      (finding) => `
        <section class="finding">
          <div class="finding-head">
            <h3>${escapeHtml(finding.title)}</h3>
            <span class="badge">${escapeHtml(finding.severity)}</span>
            <span class="badge">${escapeHtml(finding.confidence)}</span>
          </div>
          <p>${escapeHtml(finding.summary)}</p>
          <p><strong>Why:</strong> ${escapeHtml(finding.rationale)}</p>
          <p><strong>Boundary:</strong> ${escapeHtml(finding.boundary)}</p>
          <p><strong>Operator impact:</strong> ${escapeHtml(finding.operatorImpact)}</p>
          <p><strong>False positive guidance:</strong> ${escapeHtml(finding.falsePositiveGuidance)}</p>
          <ul>
            ${finding.evidence
              .map(
                (item) =>
                  `<li><strong>${escapeHtml(item.label)}:</strong> ${escapeHtml(item.value)} <span class="muted">(${escapeHtml(item.pathOrCommand)})</span></li>`
              )
              .join("")}
          </ul>
        </section>
      `
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>HostGuard Linux Report</title>
    <style>
      body { font-family: "Segoe UI", sans-serif; margin: 32px; color: #132033; background: #f7fbff; }
      h1, h2, h3, p { margin-top: 0; }
      .meta, .muted { color: #5d6c80; }
      .badge { display: inline-block; margin-right: 8px; padding: 4px 8px; border-radius: 999px; background: #dbeafe; }
      .finding { background: #fff; border: 1px solid #d7e3f4; border-radius: 16px; padding: 16px; margin-bottom: 16px; }
      .finding-head { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
      .summary { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-bottom: 24px; }
      .card { background: #fff; border: 1px solid #d7e3f4; border-radius: 16px; padding: 16px; }
    </style>
  </head>
  <body>
    <h1>HostGuard Linux</h1>
    <p class="meta">Guest-visible VM posture report for scan ${escapeHtml(exported.scanId)}</p>
    <div class="summary">
      <div class="card">
        <h2>Scan</h2>
        <p>Collected: ${escapeHtml(exported.collectedAt)}</p>
        <p>Profile: ${escapeHtml(exported.profile)}</p>
        <p>Distro: ${escapeHtml(`${exported.system.distro} ${exported.system.version}`)}</p>
      </div>
      <div class="card">
        <h2>Confidence caveats</h2>
        <p>${escapeHtml(exported.posture.trustStatement)}</p>
        <p>Advisory coverage: ${escapeHtml(exported.environment.advisoryCoverage)}</p>
        <p>Omitted: ${escapeHtml(exported.omittedData.join(", "))}</p>
      </div>
    </div>
    <h2>Findings</h2>
    ${findingRows || "<p>No findings were exported.</p>"}
  </body>
</html>`;
}

export function getSuppressionState(): SuppressionRecord[] {
  return listSuppressions();
}

export function createSuppression(input: Omit<SuppressionRecord, "id" | "createdAt">): SuppressionRecord {
  const suppression: SuppressionRecord = {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    ...input
  };
  saveSuppression(suppression);
  return suppression;
}

export function removeSuppression(suppressionId: string): void {
  deleteSuppression(suppressionId);
}
