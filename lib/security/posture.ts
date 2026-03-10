import { getPolicyProfileDefinition } from "@/lib/security/profiles";
import type { Finding, PolicyProfile, PostureCategory, PostureScore, PostureSummary, Severity } from "@/lib/types";

const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 2,
  low: 5,
  medium: 11,
  high: 18,
  critical: 27
};

const CONFIDENCE_MULTIPLIER = {
  authoritative: 1,
  inferred: 0.8,
  unverifiable: 0.45
} as const;

const CATEGORY_TITLES: Record<PostureCategory, string> = {
  guestHardening: "Guest Hardening",
  exposureSurface: "Exposure Surface",
  leakageRisk: "Leakage Risk",
  observabilityConfidence: "Observability Confidence",
  unverifiableHostControls: "Unverifiable Host Controls"
};

const PROFILE_CATEGORY_MULTIPLIER: Record<PolicyProfile, Record<PostureCategory, number>> = {
  balanced: {
    guestHardening: 1,
    exposureSurface: 1,
    leakageRisk: 1,
    observabilityConfidence: 1,
    unverifiableHostControls: 1
  },
  "high-isolation": {
    guestHardening: 1,
    exposureSurface: 1.2,
    leakageRisk: 1.35,
    observabilityConfidence: 1,
    unverifiableHostControls: 1
  },
  "paranoid-lab": {
    guestHardening: 1.1,
    exposureSurface: 1.35,
    leakageRisk: 1.55,
    observabilityConfidence: 1.1,
    unverifiableHostControls: 1
  }
};

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function scoreFindings(findings: Finding[], category: PostureCategory, profile: PolicyProfile): PostureScore {
  const drivers = findings.filter((finding) => finding.categories.includes(category));

  if (category === "unverifiableHostControls") {
    const score = clampScore(100 - drivers.length * 18);
    return {
      category,
      title: CATEGORY_TITLES[category],
      score,
      summary:
        drivers.length > 0
          ? `${drivers.length} host-side controls remain outside the guest trust boundary.`
          : "No explicit host blind spots were recorded.",
      driverFindingIds: drivers.map((finding) => finding.id)
    };
  }

  if (category === "observabilityConfidence") {
    const inferredCount = findings.filter((finding) => finding.confidence === "inferred").length;
    const blindSpotCount = findings.filter((finding) => finding.confidence === "unverifiable").length;
    const score = clampScore(100 - drivers.length * 11 - inferredCount * 3 - blindSpotCount * 4);
    return {
      category,
      title: CATEGORY_TITLES[category],
      score,
      summary:
        drivers.length > 0
          ? `${drivers.length} findings indicate heuristic or limited-visibility conclusions.`
          : "Telemetry quality is strong for the current guest-visible checks.",
      driverFindingIds: drivers.map((finding) => finding.id)
    };
  }

  const multiplier = PROFILE_CATEGORY_MULTIPLIER[profile][category];
  const score = clampScore(
    100 -
      drivers.reduce((total, finding) => {
        return total + SEVERITY_WEIGHT[finding.severity] * CONFIDENCE_MULTIPLIER[finding.confidence] * multiplier;
      }, 0)
  );

  return {
    category,
    title: CATEGORY_TITLES[category],
    score,
    summary: drivers.length > 0 ? `${drivers.length} findings currently drive this category.` : "No material issues detected in this category.",
    driverFindingIds: drivers.map((finding) => finding.id)
  };
}

export function buildPostureSummary(findings: Finding[], profile: PolicyProfile): PostureSummary {
  const categories: PostureCategory[] = [
    "guestHardening",
    "exposureSurface",
    "leakageRisk",
    "observabilityConfidence",
    "unverifiableHostControls"
  ];
  const scores = categories.map((category) => scoreFindings(findings, category, profile));
  const profileMeta = getPolicyProfileDefinition(profile);
  const overallScore =
    scores
      .filter((score) => score.category !== "unverifiableHostControls")
      .reduce((total, score) => total + score.score, 0) / 4;

  return {
    generatedAt: new Date().toISOString(),
    profile,
    scores,
    overallScore: clampScore(overallScore),
    trustStatement: `${profileMeta.label} profile: authoritative findings come from guest-visible state, inferred findings describe likely exposure paths, and host-side isolation controls remain unverifiable from inside the VM.`,
    topPriorities: findings.filter((finding) => finding.severity === "critical" || finding.severity === "high").slice(0, 3).map((finding) => finding.title)
  };
}
