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
    generatedAt: string;
    expiresAt?: string;
    source: string;
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
        generatedAt: bundle.metadata.generatedAt,
        expiresAt: bundle.metadata.expiresAt,
        source: bundle.metadata.source,
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

function loadBundle(): { bundle: AdvisoryBundle; path: string } | null {
  const imported = getImportedAdvisoryPath();
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

  return {
    bundleId: loaded.bundle.metadata.id,
    generatedAt: loaded.bundle.metadata.generatedAt,
    expiresAt,
    verified,
    stale,
    source: loaded.bundle.metadata.source,
    sha256
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
  if (!bundle.metadata?.id || !bundle.metadata?.generatedAt || !Array.isArray(bundle.packages)) {
    throw new Error("Invalid advisory bundle format.");
  }

  copyFileSync(bundlePath, getImportedAdvisoryPath());
  chmodSync(getImportedAdvisoryPath(), 0o600);

  const status = getAdvisoryBundleStatus();
  if (!status) {
    throw new Error("Imported advisory bundle could not be loaded.");
  }

  return status;
}

