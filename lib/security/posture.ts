import type { Finding, PostureCategory, PostureScore, PostureSummary, Severity } from "@/lib/types";

const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 0,
  low: 5,
  medium: 10,
  high: 18,
  critical: 25
};

const CONFIDENCE_MULTIPLIER = {
  authoritative: 1,
  inferred: 0.8,
  unverifiable: 0.4
} as const;

const TITLES: Record<PostureCategory, string> = {
  guestHardening: "Guest Hardening",
  exposureSurface: "Exposure Surface",
  leakageRisk: "Leakage Risk",
  remediationReadiness: "Remediation Readiness",
  unverifiableHostControls: "Unverifiable Host Controls"
};

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

export function buildPostureSummary(findings: Finding[]): PostureSummary {
  const categories: PostureCategory[] = [
    "guestHardening",
    "exposureSurface",
    "leakageRisk",
    "remediationReadiness",
    "unverifiableHostControls"
  ];

  const scores: PostureScore[] = categories.map((category) => {
    if (category === "unverifiableHostControls") {
      const count = findings.filter((finding) => finding.boundary === "host-unverifiable").length;
      const score = clampScore(20 - count * 2);
      return {
        category,
        title: TITLES[category],
        score,
        summary: count > 0 ? `${count} host controls remain unverifiable from inside the guest.` : "No explicit host-control blind spots were recorded."
      };
    }

    let score = 100;
    for (const finding of findings) {
      if (!finding.categories.includes(category)) {
        continue;
      }
      score -= SEVERITY_WEIGHT[finding.severity] * CONFIDENCE_MULTIPLIER[finding.confidence];
      if (category === "remediationReadiness" && finding.remediation.length === 0) {
        score -= 6;
      }
    }

    const categoryFindings = findings.filter((finding) => finding.categories.includes(category));
    return {
      category,
      title: TITLES[category],
      score: clampScore(score),
      summary:
        categoryFindings.length > 0
          ? `${categoryFindings.length} findings influence this category.`
          : "No material issues detected in this category."
    };
  });

  const overallScore =
    scores
      .filter((score) => score.category !== "unverifiableHostControls")
      .reduce((total, score) => total + score.score, 0) / 4;

  return {
    generatedAt: new Date().toISOString(),
    overallScore: clampScore(overallScore),
    scores,
    trustStatement:
      "Authoritative findings come from guest-visible state. Inferred findings describe likely host-guest exposure. Host-side isolation controls remain unverifiable from inside the VM."
  };
}

