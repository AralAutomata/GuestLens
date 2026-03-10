import { analyzeSnapshot } from "@/lib/security/analyzer";
import { getLatestScan, getScanHistory, saveScan } from "@/lib/security/database";
import { requestGuestScan } from "@/lib/security/collector-client";
import { executeRemediation } from "@/lib/security/remediation";
import type { RemediationResult, StoredScan } from "@/lib/types";

export async function runFullScan(): Promise<StoredScan> {
  const snapshot = await requestGuestScan();
  const stored = analyzeSnapshot(snapshot);
  saveScan(stored);
  return stored;
}

export function getLatestStoredScan(): StoredScan | null {
  return getLatestScan();
}

export function getStoredHistory() {
  return getScanHistory();
}

export async function runRemediationByActionId(actionId: string, execute: boolean): Promise<{
  remediation: RemediationResult;
  latestScan: StoredScan | null;
}> {
  const latest = getLatestScan();
  if (!latest) {
    throw new Error("No scan results are available. Run a scan first.");
  }

  const finding = latest.findings.find((item) => item.remediation.some((action) => action.id === actionId));
  if (!finding) {
    throw new Error(`No remediation action '${actionId}' exists in the latest scan.`);
  }

  const action = finding.remediation.find((item) => item.id === actionId);
  if (!action) {
    throw new Error(`No remediation action '${actionId}' exists in the latest scan.`);
  }

  const remediation = execute
    ? executeRemediation(action, latest.snapshot, finding)
    : {
        actionId,
        executed: false,
        success: true,
        output: action.commands.length > 0 ? action.commands : ["No direct commands are available; follow the manual guidance."],
        beforeEvidence: finding.evidence,
        afterEvidence: finding.evidence
      };

  const latestScan = execute && remediation.success ? await runFullScan() : latest;
  return { remediation, latestScan };
}
