import { buildFindingGroups, runChecks } from "@/lib/security/checks";
import { buildPostureSummary } from "@/lib/security/posture";
import type { PolicyProfile, ScanSnapshot, StoredScan } from "@/lib/types";

export function analyzeSnapshot(snapshot: ScanSnapshot, profile: PolicyProfile): StoredScan {
  const findings = runChecks(snapshot, profile);
  const groups = buildFindingGroups(findings);
  const posture = buildPostureSummary(findings, profile);

  return {
    scanId: snapshot.id,
    profile,
    snapshot,
    findings,
    groups,
    posture,
    delta: null
  };
}
