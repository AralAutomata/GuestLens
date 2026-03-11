import { describe, expect, test } from "bun:test";

import { runChecks } from "../lib/security/checks";
import { baseSnapshot } from "./fixtures/snapshots";

describe("fingerprint stability", () => {
  test("same snapshot produces identical fingerprints across runs", () => {
    const s = baseSnapshot();
    const first = runChecks(s, "balanced");
    const second = runChecks(baseSnapshot(), "balanced");

    expect(first.length).toBe(second.length);
    for (let i = 0; i < first.length; i++) {
      expect(first[i].fingerprint).toBe(second[i].fingerprint);
    }
  });

  test("fingerprints are valid 64-char hex SHA-256", () => {
    const findings = runChecks(baseSnapshot(), "balanced");
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test("different evidence produces different fingerprints", () => {
    const s1 = baseSnapshot();
    const s2 = baseSnapshot();
    s2.security.lsm = { selinuxMode: "disabled", appArmorEnabled: false, appArmorProfilesLoaded: false };

    const f1 = runChecks(s1, "balanced");
    const f2 = runChecks(s2, "balanced");

    // s2 has additional/different findings, so fingerprints should differ
    const fp1Set = new Set(f1.map((f) => f.fingerprint));
    const fp2Set = new Set(f2.map((f) => f.fingerprint));
    // The LSM finding in f2 should not exist in f1
    const lsmFinding = f2.find((f) => f.ruleId.startsWith("guest.lsm."));
    expect(lsmFinding).toBeDefined();
    expect(fp1Set.has(lsmFinding!.fingerprint)).toBe(false);
  });

  test("profile changes do not affect fingerprint when evidence is identical", () => {
    // Fingerprint includes ruleId, boundary, impactedSurfaces, evidence — NOT profile
    // But profile can change severity which is NOT in fingerprint
    // So same snapshot + different profile should give same fingerprint for same rule
    const s = baseSnapshot();
    s.security.lsm = { selinuxMode: "disabled", appArmorEnabled: false, appArmorProfilesLoaded: false };

    const balanced = runChecks(s, "balanced");
    const paranoid = runChecks(s, "paranoid-lab");

    const bLsm = balanced.find((f) => f.ruleId.startsWith("guest.lsm."));
    const pLsm = paranoid.find((f) => f.ruleId.startsWith("guest.lsm."));
    expect(bLsm).toBeDefined();
    expect(pLsm).toBeDefined();
    expect(bLsm!.fingerprint).toBe(pLsm!.fingerprint);
  });

  test("each finding in a scan has a unique fingerprint", () => {
    const s = baseSnapshot();
    s.security.lsm = { selinuxMode: "disabled", appArmorEnabled: false, appArmorProfilesLoaded: false };
    s.security.firewall.defaultDenyInbound = false;
    s.security.firewall.inferenceQuality = "heuristic";

    const findings = runChecks(s, "balanced");
    const fingerprints = findings.map((f) => f.fingerprint);
    const unique = new Set(fingerprints);
    expect(unique.size).toBe(fingerprints.length);
  });
});
