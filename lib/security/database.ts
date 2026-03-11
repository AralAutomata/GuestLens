import { chmodSync, existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import { getDatabasePath } from "@/lib/security/state";
import { DEFAULT_POLICY_PROFILE } from "@/lib/security/profiles";
import type {
  EvidenceRecord,
  Finding,
  FindingGroup,
  PolicyProfile,
  PostureSummary,
  ScanDelta,
  ScanSnapshot,
  StoredScan,
  SuppressionRecord
} from "@/lib/types";

declare global {
  // eslint-disable-next-line no-var
  var __insideJobVmDb: DatabaseSync | undefined;
}

function openDatabase(): DatabaseSync {
  if (!global.__insideJobVmDb) {
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
      CREATE TABLE IF NOT EXISTS evidence (
        evidence_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        PRIMARY KEY (evidence_id, finding_id, scan_id)
      );
      CREATE TABLE IF NOT EXISTS scan_groups (
        group_id TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        group_json TEXT NOT NULL,
        PRIMARY KEY (group_id, scan_id)
      );
      CREATE TABLE IF NOT EXISTS scan_deltas (
        to_scan_id TEXT PRIMARY KEY,
        from_scan_id TEXT,
        delta_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS suppressions (
        suppression_id TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        match_value TEXT NOT NULL,
        reason TEXT,
        author TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT
      );
    `);
    if (existsSync(dbPath)) {
      chmodSync(dbPath, 0o600);
    }
    global.__insideJobVmDb = db;
  }

  return global.__insideJobVmDb;
}

function hydrateScan(scanId: string, snapshotJson: string, postureJson: string): StoredScan {
  const db = openDatabase();
  const findingRows = db
    .prepare(`SELECT finding_json FROM findings WHERE scan_id = ? ORDER BY rowid ASC`)
    .all(scanId) as Array<{ finding_json: string }>;
  const groupRows = db
    .prepare(`SELECT group_json FROM scan_groups WHERE scan_id = ? ORDER BY rowid ASC`)
    .all(scanId) as Array<{ group_json: string }>;
  const deltaRow = db
    .prepare(`SELECT delta_json FROM scan_deltas WHERE to_scan_id = ?`)
    .get(scanId) as { delta_json: string } | undefined;
  const posture = JSON.parse(postureJson) as PostureSummary;

  return {
    scanId,
    profile: posture.profile,
    snapshot: JSON.parse(snapshotJson) as ScanSnapshot,
    posture,
    findings: findingRows.map((row) => JSON.parse(row.finding_json) as Finding),
    groups: groupRows.map((row) => JSON.parse(row.group_json) as FindingGroup),
    delta: deltaRow ? (JSON.parse(deltaRow.delta_json) as ScanDelta) : null
  };
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
  const insertEvidence = db.prepare(`
    INSERT INTO evidence (evidence_id, finding_id, scan_id, evidence_json)
    VALUES (?, ?, ?, ?)
  `);
  const insertGroup = db.prepare(`
    INSERT INTO scan_groups (group_id, scan_id, group_json)
    VALUES (?, ?, ?)
  `);
  const insertDelta = db.prepare(`
    INSERT INTO scan_deltas (to_scan_id, from_scan_id, delta_json)
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
    for (const evidence of finding.evidence) {
      insertEvidence.run(evidence.id, finding.id, stored.scanId, JSON.stringify(evidence));
    }
  }

  for (const group of stored.groups) {
    insertGroup.run(group.id, stored.scanId, JSON.stringify(group));
  }

  if (stored.delta) {
    insertDelta.run(stored.scanId, stored.delta.fromScanId, JSON.stringify(stored.delta));
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

  return hydrateScan(scanRow.scan_id, scanRow.snapshot_json, scanRow.posture_json);
}

export function getScanById(scanId: string): StoredScan | null {
  const db = openDatabase();
  const scanRow = db
    .prepare(`SELECT scan_id, snapshot_json, posture_json FROM scans WHERE scan_id = ?`)
    .get(scanId) as { scan_id: string; snapshot_json: string; posture_json: string } | undefined;

  if (!scanRow) {
    return null;
  }

  return hydrateScan(scanRow.scan_id, scanRow.snapshot_json, scanRow.posture_json);
}

export function getEvidenceForFinding(scanId: string, findingId: string): EvidenceRecord[] {
  const db = openDatabase();
  const rows = db
    .prepare(`SELECT evidence_json FROM evidence WHERE scan_id = ? AND finding_id = ? ORDER BY rowid ASC`)
    .all(scanId, findingId) as Array<{ evidence_json: string }>;
  return rows.map((row) => JSON.parse(row.evidence_json) as EvidenceRecord);
}

export function getScanHistory(limit = 12): Array<{
  scanId: string;
  collectedAt: string;
  overallScore: number;
  findingCount: number;
  profile: PolicyProfile;
  newFindingCount: number;
  resolvedFindingCount: number;
  changedFindingCount: number;
}> {
  const db = openDatabase();
  const rows = db
    .prepare(`
      SELECT scans.scan_id AS scan_id, scans.collected_at AS collected_at, scans.posture_json AS posture_json,
        COUNT(findings.finding_id) AS finding_count, scan_deltas.delta_json AS delta_json
      FROM scans
      LEFT JOIN findings ON findings.scan_id = scans.scan_id
      LEFT JOIN scan_deltas ON scan_deltas.to_scan_id = scans.scan_id
      GROUP BY scans.scan_id
      ORDER BY scans.collected_at DESC
      LIMIT ?
    `)
    .all(limit) as Array<{
      scan_id: string;
      collected_at: string;
      posture_json: string;
      finding_count: number;
      delta_json: string | null;
    }>;

  return rows.map((row) => {
    const posture = JSON.parse(row.posture_json) as PostureSummary;
    const delta = row.delta_json ? (JSON.parse(row.delta_json) as ScanDelta) : null;
    return {
      scanId: row.scan_id,
      collectedAt: row.collected_at,
      overallScore: posture.overallScore,
      findingCount: row.finding_count,
      profile: posture.profile,
      newFindingCount: delta?.summary.newCount ?? row.finding_count,
      resolvedFindingCount: delta?.summary.resolvedCount ?? 0,
      changedFindingCount: delta?.summary.changedCount ?? 0
    };
  });
}

export function getStoredDelta(scanId: string): ScanDelta | null {
  const db = openDatabase();
  const row = db
    .prepare(`SELECT delta_json FROM scan_deltas WHERE to_scan_id = ?`)
    .get(scanId) as { delta_json: string } | undefined;
  return row ? (JSON.parse(row.delta_json) as ScanDelta) : null;
}

export function getActiveProfile(): PolicyProfile {
  const db = openDatabase();
  const row = db.prepare(`SELECT value_json FROM settings WHERE key = 'active-profile'`).get() as { value_json: string } | undefined;
  return row ? (JSON.parse(row.value_json) as PolicyProfile) : DEFAULT_POLICY_PROFILE;
}

export function setActiveProfile(profile: PolicyProfile): void {
  const db = openDatabase();
  db.prepare(`
    INSERT INTO settings (key, value_json)
    VALUES ('active-profile', ?)
    ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json
  `).run(JSON.stringify(profile));
}

export function listSuppressions(): SuppressionRecord[] {
  const db = openDatabase();
  const rows = db
    .prepare(`
      SELECT suppression_id, scope, match_value, reason, author, created_at, expires_at
      FROM suppressions
      ORDER BY created_at DESC
    `)
    .all() as Array<{
      suppression_id: string;
      scope: SuppressionRecord["scope"];
      match_value: string;
      reason: string | null;
      author: string | null;
      created_at: string;
      expires_at: string | null;
    }>;

  const now = Date.now();
  return rows
    .filter((row) => !row.expires_at || Date.parse(row.expires_at) > now)
    .map((row) => ({
      id: row.suppression_id,
      scope: row.scope,
      matchValue: row.match_value,
      reason: row.reason ?? undefined,
      author: row.author ?? undefined,
      createdAt: row.created_at,
      expiresAt: row.expires_at
    }));
}

export function saveSuppression(suppression: SuppressionRecord): void {
  const db = openDatabase();
  db.prepare(`
    INSERT INTO suppressions (suppression_id, scope, match_value, reason, author, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    suppression.id,
    suppression.scope,
    suppression.matchValue,
    suppression.reason ?? null,
    suppression.author ?? null,
    suppression.createdAt,
    suppression.expiresAt ?? null
  );
}

export function deleteSuppression(suppressionId: string): void {
  const db = openDatabase();
  db.prepare(`DELETE FROM suppressions WHERE suppression_id = ?`).run(suppressionId);
}
