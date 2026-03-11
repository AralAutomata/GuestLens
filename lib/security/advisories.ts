import { createHash, verify } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, readFileSync } from "node:fs";

import type { AdvisoryBundleStatus, PackageRecord, Severity, VulnerabilityMatch } from "@/lib/types";
import { getBundledAdvisoryPath, getImportedAdvisoryPath } from "@/lib/security/state";

interface AdvisoryRecord {
  name: string;
  severity: Severity;
  summary: string;
  cves: string[];
  matchStrategy?: "exact" | "prefix";
}

interface AdvisoryBundle {
  metadata: {
    id: string;
    generatorVersion?: string;
    generatedAt: string;
    expiresAt?: string;
    source: string;
    supportScope?: string[];
    trust?: {
      keyId?: string;
      algorithm?: "ed25519";
      signature?: string;
    };
  };
  packages: AdvisoryRecord[];
}

const TRUSTED_KEYS: Record<string, string> = {};

function canonicalizeBundle(bundle: AdvisoryBundle): string {
  return JSON.stringify(
    {
      metadata: {
        id: bundle.metadata.id,
        generatorVersion: bundle.metadata.generatorVersion,
        generatedAt: bundle.metadata.generatedAt,
        expiresAt: bundle.metadata.expiresAt,
        source: bundle.metadata.source,
        supportScope: bundle.metadata.supportScope,
        trust: {
          keyId: bundle.metadata.trust?.keyId,
          algorithm: bundle.metadata.trust?.algorithm
        }
      },
      packages: bundle.packages
    },
    null,
    0
  );
}

function validateBundle(bundle: AdvisoryBundle): string[] {
  const issues: string[] = [];

  if (!bundle.metadata?.id) {
    issues.push("Bundle metadata is missing an id.");
  }
  if (!bundle.metadata?.generatedAt || Number.isNaN(Date.parse(bundle.metadata.generatedAt))) {
    issues.push("Bundle generatedAt is missing or invalid.");
  }
  if (bundle.metadata?.expiresAt && Number.isNaN(Date.parse(bundle.metadata.expiresAt))) {
    issues.push("Bundle expiresAt is invalid.");
  }
  if (!Array.isArray(bundle.packages)) {
    issues.push("Bundle packages payload is invalid.");
  }

  return issues;
}

function loadBundle(): { bundle: AdvisoryBundle; path: string } | null {
  const imported = getImportedAdvisoryPath(false);
  const bundled = getBundledAdvisoryPath();
  const target = existsSync(imported) ? imported : bundled;
  if (!existsSync(target)) {
    return null;
  }

  const bundle = JSON.parse(readFileSync(target, "utf8")) as AdvisoryBundle;
  return { bundle, path: target };
}

export function getAdvisoryBundleStatus(): AdvisoryBundleStatus | null {
  const loaded = loadBundle();
  if (!loaded) {
    return null;
  }

  const issues = validateBundle(loaded.bundle);
  const payload = canonicalizeBundle(loaded.bundle);
  const sha256 = createHash("sha256").update(payload).digest("hex");
  const expiresAt = loaded.bundle.metadata.expiresAt;
  const stale = expiresAt ? Date.now() > Date.parse(expiresAt) : Date.now() - Date.parse(loaded.bundle.metadata.generatedAt) > 30 * 24 * 60 * 60 * 1000;

  let verified = false;
  const signature = loaded.bundle.metadata.trust?.signature;
  const keyId = loaded.bundle.metadata.trust?.keyId;
  if (signature && keyId && TRUSTED_KEYS[keyId]) {
    verified = verify(
      null,
      Buffer.from(payload),
      TRUSTED_KEYS[keyId],
      Buffer.from(signature, "base64")
    );
  }

  const supportScope = loaded.bundle.metadata.supportScope ?? [];
  const coverage = supportScope.length === 0 ? "limited" : supportScope.some((scope) => /debian|ubuntu|rhel|centos|fedora|rocky|alma/i.test(scope)) ? "supported" : "unsupported";

  return {
    bundleId: loaded.bundle.metadata.id,
    generatorVersion: loaded.bundle.metadata.generatorVersion,
    generatedAt: loaded.bundle.metadata.generatedAt,
    expiresAt,
    verified,
    valid: issues.length === 0,
    stale,
    source: loaded.bundle.metadata.source,
    sha256
    ,
    supportScope,
    coverage,
    issues: issues.concat(
      loaded.bundle.metadata.trust?.signature && !verified ? ["Bundle signature could not be verified with a trusted key."] : [],
      stale ? ["Bundle is stale for security decision-making."] : [],
      coverage === "unsupported" ? ["Bundle does not declare coverage for any supported distro family."] : []
    )
  };
}

export function matchVulnerabilities(packages: PackageRecord[]): VulnerabilityMatch[] {
  const loaded = loadBundle();
  if (!loaded) {
    return [];
  }

  const matches: VulnerabilityMatch[] = [];
  for (const advisory of loaded.bundle.packages) {
    const hit = packages.find((pkg) =>
      advisory.matchStrategy === "prefix" ? pkg.name.startsWith(advisory.name) : pkg.name === advisory.name
    );
    if (!hit) {
      continue;
    }

    matches.push({
      packageName: hit.name,
      severity: advisory.severity,
      summary: advisory.summary,
      cves: advisory.cves,
      source: loaded.bundle.metadata.id
    });
  }

  return matches;
}

export function importAdvisoryBundle(bundlePath: string): AdvisoryBundleStatus {
  const raw = readFileSync(bundlePath, "utf8");
  const bundle = JSON.parse(raw) as AdvisoryBundle;
  const issues = validateBundle(bundle);
  if (issues.length > 0) {
    throw new Error(`Invalid advisory bundle format. ${issues[0]}`);
  }

  copyFileSync(bundlePath, getImportedAdvisoryPath());
  chmodSync(getImportedAdvisoryPath(), 0o600);

  const status = getAdvisoryBundleStatus();
  if (!status) {
    throw new Error("Imported advisory bundle could not be loaded.");
  }

  return status;
}
