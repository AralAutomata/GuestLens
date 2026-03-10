import { analyzeSnapshot } from "@/lib/security/analyzer";
import { getLatestScan, getScanHistory, saveScan } from "@/lib/security/database";
import { requestGuestScan } from "@/lib/security/collector-client";
import type { StoredScan } from "@/lib/types";

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
