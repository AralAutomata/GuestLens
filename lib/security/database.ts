import { chmodSync, existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import { getDatabasePath } from "@/lib/security/state";
import type { Finding, PostureSummary, ScanSnapshot, StoredScan } from "@/lib/types";

declare global {
  // eslint-disable-next-line no-var
  var __hostguardDb: DatabaseSync | undefined;
}

function openDatabase(): DatabaseSync {
  if (!global.__hostguardDb) {
    const dbPath = getDatabasePath();
    const db = new DatabaseSync(dbPath);
    db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        collected_at TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        posture_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        finding_json TEXT NOT NULL,
        PRIMARY KEY (finding_id, scan_id)
      );
    `);
    if (existsSync(dbPath)) {
      chmodSync(dbPath, 0o600);
    }
    global.__hostguardDb = db;
  }

  return global.__hostguardDb;
}

export function saveScan(stored: StoredScan): void {
  const db = openDatabase();
  const insertScan = db.prepare(`
    INSERT INTO scans (scan_id, collected_at, snapshot_json, posture_json)
    VALUES (?, ?, ?, ?)
  `);
  const insertFinding = db.prepare(`
    INSERT INTO findings (finding_id, scan_id, finding_json)
    VALUES (?, ?, ?)
  `);

  insertScan.run(
    stored.scanId,
    stored.snapshot.collectedAt,
    JSON.stringify(stored.snapshot),
    JSON.stringify(stored.posture)
  );

  for (const finding of stored.findings) {
    insertFinding.run(finding.id, stored.scanId, JSON.stringify(finding));
  }
}

export function getLatestScan(): StoredScan | null {
  const db = openDatabase();
  const scanRow = db
    .prepare(`SELECT scan_id, snapshot_json, posture_json FROM scans ORDER BY collected_at DESC LIMIT 1`)
    .get() as { scan_id: string; snapshot_json: string; posture_json: string } | undefined;

  if (!scanRow) {
    return null;
  }

  const findingRows = db
    .prepare(`SELECT finding_json FROM findings WHERE scan_id = ? ORDER BY rowid ASC`)
    .all(scanRow.scan_id) as Array<{ finding_json: string }>;

  return {
    scanId: scanRow.scan_id,
    snapshot: JSON.parse(scanRow.snapshot_json) as ScanSnapshot,
    posture: JSON.parse(scanRow.posture_json) as PostureSummary,
    findings: findingRows.map((row) => JSON.parse(row.finding_json) as Finding)
  };
}

export function getScanHistory(limit = 10): Array<{
  scanId: string;
  collectedAt: string;
  overallScore: number;
  findingCount: number;
}> {
  const db = openDatabase();
  const rows = db
    .prepare(`
      SELECT scans.scan_id AS scan_id, scans.collected_at AS collected_at, scans.posture_json AS posture_json,
        COUNT(findings.finding_id) AS finding_count
      FROM scans
      LEFT JOIN findings ON findings.scan_id = scans.scan_id
      GROUP BY scans.scan_id
      ORDER BY scans.collected_at DESC
      LIMIT ?
    `)
    .all(limit) as Array<{ scan_id: string; collected_at: string; posture_json: string; finding_count: number }>;

  return rows.map((row) => ({
    scanId: row.scan_id,
    collectedAt: row.collected_at,
    overallScore: (JSON.parse(row.posture_json) as PostureSummary).overallScore,
    findingCount: row.finding_count
  }));
}

