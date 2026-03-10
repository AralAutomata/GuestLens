import { importAdvisoryBundle } from "@/lib/security/advisories";

const bundlePath = process.argv[2];

if (!bundlePath) {
  console.error("Usage: bun run advisories:import /path/to/advisories.bundle.json");
  process.exit(1);
}

try {
  const status = importAdvisoryBundle(bundlePath);
  console.log(`Imported advisory bundle ${status.bundleId}`);
  console.log(`Generated at: ${status.generatedAt}`);
  console.log(`Verified: ${status.verified}`);
  console.log(`SHA256: ${status.sha256}`);
} catch (error) {
  console.error(error instanceof Error ? error.message : "Failed to import advisory bundle.");
  process.exit(1);
}

