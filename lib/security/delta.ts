import type { ConfidenceLevel, Finding, ScanDelta, StoredScan } from "@/lib/types";

function severityRank(severity: Finding["severity"]): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(severity);
}

function confidenceRank(confidence: ConfidenceLevel): number {
  return ["unverifiable", "inferred", "authoritative"].indexOf(confidence);
}

function signatureForFinding(finding: Finding): string {
  return JSON.stringify({
    fingerprint: finding.fingerprint,
    severity: finding.severity,
    confidence: finding.confidence,
    summary: finding.summary,
    remediation: finding.remediation.map((action) => `${action.id}:${action.commands.join("|")}`),
    impactedSurfaces: finding.impactedSurfaces
  });
}

export function buildScanDelta(previous: StoredScan | null, current: StoredScan): ScanDelta {
  if (!previous) {
    const suppressedFindingIds = current.findings.filter((finding) => finding.suppressed).map((finding) => finding.id);
    return {
      fromScanId: null,
      toScanId: current.scanId,
      newFindingIds: current.findings.map((finding) => finding.id),
      resolvedFindingIds: [],
      changedFindingIds: [],
      suppressedFindingIds,
      severityUpgrades: [],
      confidenceDowngrades: [],
      unchangedCount: 0,
      summary: {
        newCount: current.findings.length,
        resolvedCount: 0,
        changedCount: 0,
        suppressedCount: suppressedFindingIds.length,
        severityUpgradeCount: 0,
        confidenceDowngradeCount: 0
      }
    };
  }

  const previousById = new Map(previous.findings.map((finding) => [finding.id, finding]));
  const currentById = new Map(current.findings.map((finding) => [finding.id, finding]));

  const newFindingIds = current.findings.filter((finding) => !previousById.has(finding.id)).map((finding) => finding.id);
  const resolvedFindingIds = previous.findings.filter((finding) => !currentById.has(finding.id)).map((finding) => finding.id);
  const changedFindingIds: string[] = [];
  const suppressedFindingIds = current.findings.filter((finding) => finding.suppressed).map((finding) => finding.id);
  const severityUpgrades: string[] = [];
  const confidenceDowngrades: string[] = [];
  let unchangedCount = 0;

  for (const finding of current.findings) {
    const previousFinding = previousById.get(finding.id);
    if (!previousFinding) {
      continue;
    }

    const changed = signatureForFinding(previousFinding) !== signatureForFinding(finding);
    if (changed) {
      changedFindingIds.push(finding.id);
    } else {
      unchangedCount += 1;
    }

    if (severityRank(finding.severity) > severityRank(previousFinding.severity)) {
      severityUpgrades.push(finding.id);
    }

    if (confidenceRank(finding.confidence) < confidenceRank(previousFinding.confidence)) {
      confidenceDowngrades.push(finding.id);
    }
  }

  return {
    fromScanId: previous.scanId,
    toScanId: current.scanId,
    newFindingIds,
    resolvedFindingIds,
    changedFindingIds,
    suppressedFindingIds,
    severityUpgrades,
    confidenceDowngrades,
    unchangedCount,
    summary: {
      newCount: newFindingIds.length,
      resolvedCount: resolvedFindingIds.length,
      changedCount: changedFindingIds.length,
      suppressedCount: suppressedFindingIds.length,
      severityUpgradeCount: severityUpgrades.length,
      confidenceDowngradeCount: confidenceDowngrades.length
    }
  };
}
