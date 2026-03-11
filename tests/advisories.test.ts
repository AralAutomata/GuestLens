import { describe, expect, test } from "bun:test";

import { getAdvisoryBundleStatus, matchVulnerabilities } from "../lib/security/advisories";

describe("advisories", () => {
  test("reports support coverage and generator metadata for the bundled sample bundle", () => {
    const status = getAdvisoryBundleStatus();

    expect(status).not.toBeNull();
    expect(status?.bundleId).toBe("hostguard-linux-sample-2026-03-10");
    expect(status?.generatorVersion).toBe("sample-fixture-1");
    expect(status?.coverage).toBe("supported");
    expect(status?.supportScope).toContain("debian-12");
  });

  test("matches package advisories from the bundled sample bundle", () => {
    const matches = matchVulnerabilities([
      {
        name: "openssh-server",
        version: "9.2p1",
        manager: "dpkg",
        observedAt: "2026-03-10T12:00:00.000Z",
        collectedFrom: "dpkg-query -W"
      }
    ]);

    expect(matches).toHaveLength(1);
    expect(matches[0]?.packageName).toBe("openssh-server");
    expect(matches[0]?.severity).toBe("high");
  });
});
