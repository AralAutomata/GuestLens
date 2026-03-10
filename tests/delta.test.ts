import { describe, expect, test } from "bun:test";

import { buildScanDelta } from "../lib/security/delta";
import type { Finding, StoredScan } from "../lib/types";

function finding(id: string, severity: Finding["severity"], confidence: Finding["confidence"]): Finding {
  return {
    id,
    ruleId: id,
    groupKey: "test",
    title: id,
    summary: id,
    severity,
    confidence,
    certaintyReason: "test",
    boundary: "guest",
    categories: ["guestHardening"],
    profile: "balanced",
    impactedSurfaces: [id],
    evidence: [],
    rationale: "test",
    operatorImpact: "test",
    falsePositiveGuidance: "test",
    remediation: [],
    riskFactors: [],
    relatedFindingIds: [],
    safeForAutomationLater: false,
    createdAt: "2026-03-10T00:00:00.000Z",
    introducedInScan: "scan-a"
  };
}

function scan(scanId: string, findings: Finding[]): StoredScan {
  return {
    scanId,
    profile: "balanced",
    snapshot: {
      id: scanId,
      collectedAt: "2026-03-10T00:00:00.000Z",
      collectorVersion: "0.2.0",
      system: {
        distro: "test",
        version: "1",
        kernelRelease: "1",
        kernelCommandLine: "",
        secureBootState: "enabled",
        seccompAvailable: true
      },
      packages: [],
      services: [],
      mounts: [],
      network: {
        hostname: "test",
        dnsServers: [],
      routes: [],
      neighbors: [],
      listeningSockets: [],
      publicListeningSockets: [],
      discoveryListeningSockets: [],
      metadataRoutePresent: false,
      defaultGatewayType: "unknown",
      bridgeLikely: false,
      multicastExposure: false
      },
      filePermissionIssues: [],
      security: {
        lsm: {
          selinuxMode: "enforcing",
          appArmorEnabled: true,
          appArmorProfilesLoaded: true
        },
        firewall: {
        backend: "nftables",
        manager: "nftables",
        rulesPresent: true,
        inspectionAvailable: true,
        defaultDenyInbound: true,
        defaultDenyOutbound: false,
          inputPolicy: "drop",
          outputPolicy: "accept",
          inferenceQuality: "exact",
          activeManagers: [],
          rawSummary: [],
          source: "nft",
          collectedFrom: "nft list ruleset",
          parser: "regex-policy"
        },
        ssh: {
          installed: false,
          directives: []
        },
        sudoers: {
          nopasswdEntries: []
        }
      },
      virtualization: {
        qemuGuestAgent: false,
        guestAgentChannels: [],
        spiceVdagent: false,
        clipboardIntegrationPossible: false,
        sharedFolderMounts: [],
        vsockEnabled: false,
        serialChannels: [],
        passthroughHints: [],
        timeSyncHints: [],
        sharedMemoryHints: [],
        rngDevicePresent: true,
        ballooningEnabled: false
      },
      advisoryBundle: null,
      vulnerabilities: []
    },
    findings,
    groups: [],
    posture: {
      generatedAt: "2026-03-10T00:00:00.000Z",
      profile: "balanced",
      scores: [],
      overallScore: 90,
      trustStatement: "test",
      topPriorities: []
    },
    delta: null
  };
}

describe("buildScanDelta", () => {
  test("tracks new, resolved, and changed findings", () => {
    const previous = scan("scan-a", [finding("one", "medium", "authoritative"), finding("two", "low", "authoritative")]);
    const current = scan("scan-b", [finding("one", "high", "authoritative"), finding("three", "medium", "inferred")]);

    const delta = buildScanDelta(previous, current);

    expect(delta.newFindingIds).toEqual(["three"]);
    expect(delta.resolvedFindingIds).toEqual(["two"]);
    expect(delta.changedFindingIds).toContain("one");
    expect(delta.severityUpgrades).toContain("one");
  });
});
