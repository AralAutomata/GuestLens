"use client";

import { useEffect, useState, useTransition } from "react";

import type {
  AdvisoryBundleStatus,
  EnvironmentMetadata,
  Finding,
  FindingGroup,
  PolicyProfile,
  PolicyProfileDefinition,
  PostureSummary,
  ScanDelta,
  SuppressionRecord
} from "@/lib/types";

interface HistoryEntry {
  scanId: string;
  collectedAt: string;
  overallScore: number;
  findingCount: number;
  profile: PolicyProfile;
  newFindingCount: number;
  resolvedFindingCount: number;
  changedFindingCount: number;
}

interface PostureResponse {
  posture: PostureSummary | null;
  scanId: string | null;
  collectedAt: string | null;
  profile: PolicyProfile | null;
  environment: EnvironmentMetadata | null;
  advisoryBundle: AdvisoryBundleStatus | null;
  delta: ScanDelta | null;
}

interface FindingsResponse {
  scanId: string | null;
  profile: PolicyProfile | null;
  findings: Finding[];
  groups: FindingGroup[];
  delta: ScanDelta | null;
}

interface HistoryResponse {
  history: HistoryEntry[];
}

interface ProfilesResponse {
  activeProfile: PolicyProfile;
  profiles: PolicyProfileDefinition[];
}

interface SuppressionsResponse {
  suppressions: SuppressionRecord[];
}

interface DiffResponse {
  diff: ScanDelta;
}

type SeverityFilter = "all" | Finding["severity"];
type ConfidenceFilter = "all" | Finding["confidence"];
type BoundaryFilter = "all" | Finding["boundary"];

function scoreClass(score: number): string {
  if (score >= 80) {
    return "score-good";
  }
  if (score >= 55) {
    return "score-warn";
  }
  return "score-bad";
}

function formatDate(value: string | null): string {
  if (!value) {
    return "No scans yet";
  }
  return new Date(value).toLocaleString();
}

function countBySeverity(findings: Finding[], severity: Finding["severity"]): number {
  return findings.filter((finding) => finding.severity === severity).length;
}

function deltaSummary(delta: ScanDelta | null): string {
  if (!delta) {
    return "No previous scan available for comparison.";
  }
  if (delta.fromScanId === null) {
    return "Initial baseline captured.";
  }
  return `${delta.summary.newCount} new, ${delta.summary.resolvedCount} resolved, ${delta.summary.changedCount} changed.`;
}

export function Dashboard() {
  const [posture, setPosture] = useState<PostureResponse>({
    posture: null,
    scanId: null,
    collectedAt: null,
    profile: null,
    environment: null,
    advisoryBundle: null,
    delta: null
  });
  const [findings, setFindings] = useState<FindingsResponse>({
    scanId: null,
    profile: null,
    findings: [],
    groups: [],
    delta: null
  });
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [profileState, setProfileState] = useState<ProfilesResponse>({
    activeProfile: "balanced",
    profiles: []
  });
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [confidenceFilter, setConfidenceFilter] = useState<ConfidenceFilter>("all");
  const [boundaryFilter, setBoundaryFilter] = useState<BoundaryFilter>("all");
  const [showNewOnly, setShowNewOnly] = useState(false);
  const [hideSuppressed, setHideSuppressed] = useState(true);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const [suppressions, setSuppressions] = useState<SuppressionRecord[]>([]);
  const [compareFrom, setCompareFrom] = useState<string | null>(null);
  const [compareTo, setCompareTo] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ScanDelta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  async function loadAll() {
    setError(null);
    const [postureResponse, findingsResponse, historyResponse, profilesResponse, suppressionsResponse] = await Promise.all([
      fetch("/api/posture", { cache: "no-store" }),
      fetch("/api/findings", { cache: "no-store" }),
      fetch("/api/history", { cache: "no-store" }),
      fetch("/api/profiles", { cache: "no-store" }),
      fetch("/api/suppressions", { cache: "no-store" })
    ]);

    if (!postureResponse.ok || !findingsResponse.ok || !historyResponse.ok || !profilesResponse.ok || !suppressionsResponse.ok) {
      throw new Error("Failed to load one or more dashboard resources.");
    }

    setPosture((await postureResponse.json()) as PostureResponse);
    setFindings((await findingsResponse.json()) as FindingsResponse);
    const nextHistory = ((await historyResponse.json()) as HistoryResponse).history;
    setHistory(nextHistory);
    setProfileState((await profilesResponse.json()) as ProfilesResponse);
    setSuppressions(((await suppressionsResponse.json()) as SuppressionsResponse).suppressions);
    setCompareTo((current) => current ?? nextHistory[0]?.scanId ?? null);
    setCompareFrom((current) => current ?? nextHistory[1]?.scanId ?? nextHistory[0]?.scanId ?? null);
  }

  async function runScan() {
    startTransition(async () => {
      setError(null);
      try {
        const response = await fetch("/api/scan", { method: "POST" });
        if (!response.ok) {
          throw new Error(await response.text());
        }
        await loadAll();
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : "Scan failed.");
      }
    });
  }

  async function updateProfile(profile: PolicyProfile) {
    startTransition(async () => {
      setError(null);
      try {
        const response = await fetch("/api/profile", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ profile })
        });
        if (!response.ok) {
          throw new Error(await response.text());
        }
        await loadAll();
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : "Profile update failed.");
      }
    });
  }

  async function copyCommand(command: string) {
    try {
      await navigator.clipboard.writeText(command);
      setCopiedCommand(command);
      window.setTimeout(() => setCopiedCommand((current) => (current === command ? null : current)), 1500);
    } catch {
      setError("Clipboard write failed.");
    }
  }

  async function createSuppressionForFinding(finding: Finding, scope: "rule" | "fingerprint") {
    const reason = window.prompt("Optional suppression reason", "Accepted local exception") ?? undefined;
    startTransition(async () => {
      setError(null);
      try {
        const response = await fetch("/api/suppressions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scope,
            matchValue: scope === "rule" ? finding.ruleId : finding.fingerprint,
            reason
          })
        });
        if (!response.ok) {
          throw new Error(await response.text());
        }
        await loadAll();
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : "Suppression update failed.");
      }
    });
  }

  async function removeSuppressionById(suppressionId: string) {
    startTransition(async () => {
      setError(null);
      try {
        const response = await fetch(`/api/suppressions?id=${encodeURIComponent(suppressionId)}`, {
          method: "DELETE"
        });
        if (!response.ok) {
          throw new Error(await response.text());
        }
        await loadAll();
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : "Suppression removal failed.");
      }
    });
  }

  useEffect(() => {
    loadAll().catch((caught) => {
      setError(caught instanceof Error ? caught.message : "Failed to load dashboard.");
    });
  }, []);

  useEffect(() => {
    if (!compareTo) {
      setComparison(null);
      return;
    }

    const params = new URLSearchParams();
    if (compareFrom) {
      params.set("from", compareFrom);
    }
    params.set("to", compareTo);

    fetch(`/api/diff?${params.toString()}`, { cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(await response.text());
        }
        return (await response.json()) as DiffResponse;
      })
      .then((data) => setComparison(data.diff))
      .catch(() => setComparison(null));
  }, [compareFrom, compareTo]);

  const filteredFindings = findings.findings.filter((finding) => {
    if (severityFilter !== "all" && finding.severity !== severityFilter) {
      return false;
    }
    if (confidenceFilter !== "all" && finding.confidence !== confidenceFilter) {
      return false;
    }
    if (boundaryFilter !== "all" && finding.boundary !== boundaryFilter) {
      return false;
    }
    if (showNewOnly && finding.introducedInScan !== findings.scanId) {
      return false;
    }
    if (hideSuppressed && finding.suppressed) {
      return false;
    }
    return true;
  });

  const findingMap = new Map(filteredFindings.map((finding) => [finding.id, finding]));
  const visibleGroups = findings.groups
    .map((group) => ({
      ...group,
      findingIds: group.findingIds.filter((findingId) => findingMap.has(findingId))
    }))
    .filter((group) => group.findingIds.length > 0);

  const criticalCount = countBySeverity(filteredFindings, "critical");
  const highCount = countBySeverity(filteredFindings, "high");
  const mediumCount = countBySeverity(filteredFindings, "medium");
  const activeProfile = profileState.profiles.find((item) => item.id === profileState.activeProfile);
  const comparisonSections: Array<{ key: string; label: string; ids: string[] }> = comparison
    ? [
        { key: "new", label: "New findings", ids: comparison.newFindingIds },
        { key: "resolved", label: "Resolved findings", ids: comparison.resolvedFindingIds },
        { key: "changed", label: "Changed findings", ids: comparison.changedFindingIds }
      ]
    : [];

  return (
    <main className="shell app-shell">
      <section className="topbar topbar-frame">
        <div className="topbar-copy">
          <h1 className="brand-title">GUESTLENS - Isolate Your System</h1>
          <p className="brand-description">
            Analyze your QEMU/KVM Linux systems from the inside. Discover exposed services, guest agents, 
            firewall gaps, and trust boundary violations - all locally, no cloud required.
          </p>
          <p className="brand-tagline">Secure OS Secure Data</p>
        </div>

        <div className="topbar-meta">
          <div className="topbar-badges">
            <span className="status-chip">Local-only workspace</span>
            <span className="meta">Last scan {formatDate(posture.collectedAt)}</span>
          </div>

          <div className="telemetry-panel">
            <div className="telemetry-score">
              <span className="telemetry-label">Posture Score</span>
              <div className="telemetry-value">
                <strong>{posture.posture ? `${posture.posture.overallScore}` : "--"}</strong>
                <span>/100</span>
              </div>
              <div className="telemetry-ring">
                <svg viewBox="0 0 36 36" className="circular-chart">
                  <path className="circle-bg"
                    d="M18 2.0845
                      a 15.9155 15.9155 0 0 1 0 31.831
                      a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path className="circle"
                    strokeDasharray={`${posture.posture?.overallScore ?? 0}, 100`}
                    d="M18 2.0845
                      a 15.9155 15.9155 0 0 1 0 31.831
                      a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
              </div>
            </div>
            <div className="telemetry-stats">
              <div className="telemetry-stat">
                <span className="stat-value">{filteredFindings.length}</span>
                <span className="stat-label">Findings</span>
              </div>
              <div className="telemetry-stat">
                <span className="stat-value stat-high">{criticalCount + highCount}</span>
                <span className="stat-label">High</span>
              </div>
              <div className="telemetry-stat">
                <span className="stat-value">{posture.delta?.summary.newCount ?? 0}</span>
                <span className="stat-label">New</span>
              </div>
              <div className="telemetry-stat">
                <span className="stat-value">{activeProfile?.label ?? "Balanced"}</span>
                <span className="stat-label">Profile</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="overview-grid">
        <div className="panel overview-panel">
          <div className="overview-header">
            <div>
              <div className="panel-kicker">Control Room</div>
              <h2>Current operating picture</h2>
            </div>
            <div className={`hero-score ${scoreClass(posture.posture?.overallScore ?? 0)}`}>
              {posture.posture ? `${posture.posture.overallScore}/100` : "--"}
            </div>
          </div>

          <p className="overview-trust">
            {posture.posture?.trustStatement ?? "Run a scan to generate posture, confidence boundaries, and current priorities."}
          </p>

          <div className="hero-actions action-strip">
            <button className="button" onClick={runScan} disabled={isPending}>
              {isPending ? "Scanning..." : "Run guest scan"}
            </button>
            <a
              className="button button-ghost"
              href={posture.scanId ? `/api/export?scanId=${posture.scanId}&format=html` : "#"}
            >
              Export HTML
            </a>
            <a
              className="button button-ghost"
              href={posture.scanId ? `/api/export?scanId=${posture.scanId}&format=json` : "#"}
            >
              Export JSON
            </a>
            <span className="meta">Profile: {activeProfile?.label ?? "Balanced"}</span>
          </div>

          <div className="metric-grid">
            <div className="metric-card metric-critical">
              <span className="mini-label">Immediate work</span>
              <strong>{criticalCount + highCount}</strong>
              <span>Critical and high findings in the visible queue</span>
            </div>
            <div className="metric-card metric-neutral">
              <span className="mini-label">Visible findings</span>
              <strong>{filteredFindings.length}</strong>
              <span>{visibleGroups.length} grouped issue areas</span>
            </div>
            <div className="metric-card metric-neutral">
              <span className="mini-label">Delta</span>
              <strong>{posture.delta?.summary.newCount ?? findings.findings.length}</strong>
              <span>{deltaSummary(findings.delta)}</span>
            </div>
            <div className="metric-card metric-neutral">
              <span className="mini-label">Bundle coverage</span>
              <strong>{posture.advisoryBundle?.coverage ?? "missing"}</strong>
              <span>
                {posture.advisoryBundle
                  ? posture.advisoryBundle.issues[0] ?? `Bundle ${posture.advisoryBundle.bundleId}`
                  : "No advisory bundle imported."}
              </span>
            </div>
          </div>

          {error ? <div className="error">{error}</div> : null}
        </div>

        <div className="hero-stack right-rail-stack">
          <div className="panel posture-panel">
            <div className="panel-kicker">Support scope</div>
            <h2>Environment coverage</h2>
            <div className="mini-grid compact-grid">
              <div className="mini-card">
                <span className="mini-label">Support tier</span>
                <strong>{posture.environment?.supportTier ?? "unknown"}</strong>
              </div>
              <div className="mini-card">
                <span className="mini-label">Distro family</span>
                <strong>{posture.environment?.distroFamily ?? "unknown"}</strong>
              </div>
              <div className="mini-card">
                <span className="mini-label">Package manager</span>
                <strong>{posture.environment?.packageManager ?? "unknown"}</strong>
              </div>
            </div>
            <p>
              {posture.environment
                ? `${posture.environment.distroFamily} collection running with ${posture.environment.packageManager} and ${posture.environment.initSystem}.`
                : "Run a scan to determine platform coverage and collector capabilities."}
            </p>
          </div>

          <div className="panel">
            <div className="panel-kicker">Policy profile</div>
            <h2>Severity posture</h2>
            <div className="profile-switcher">
              {profileState.profiles.map((profile) => (
                <button
                  key={profile.id}
                  className={`profile-chip ${profileState.activeProfile === profile.id ? "profile-chip-active" : ""}`}
                  onClick={() => updateProfile(profile.id)}
                  disabled={isPending}
                  type="button"
                >
                  <strong>{profile.label}</strong>
                  <span>{profile.emphasis}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="section-block">
        <div className="section-head">
          <div>
            <div className="panel-kicker">Scoring</div>
            <h2>Posture categories</h2>
          </div>
          <p className="section-copy">Each score reflects rule weight, confidence, and profile emphasis.</p>
        </div>
        <div className="score-grid">
          {posture.posture ? (
            posture.posture.scores.map((score) => (
              <div className="panel score-card" key={score.category}>
                <div className="panel-kicker">{score.category}</div>
                <h3>{score.title}</h3>
                <div className={`score-value ${scoreClass(score.score)}`}>{score.score}</div>
                <p>{score.summary}</p>
              </div>
            ))
          ) : (
            <div className="panel">
              <p>Run the first scan to populate posture categories.</p>
            </div>
          )}
        </div>
      </section>

      <section className="workspace-grid">
        <div className="panel console-main findings-panel">
          <div className="section-head">
            <div>
              <div className="panel-kicker">Queue</div>
              <h2>Findings queue</h2>
            </div>
            <p className="section-copy">
              The queue is the main working surface. Filter aggressively, review evidence, then suppress only when the exception is deliberate.
            </p>
          </div>

          <div className="filter-toolbar">
            <div className="filter-grid">
              <label className="control">
                <span className="control-label">Severity</span>
                <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as SeverityFilter)}>
                  <option value="all">All severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </label>
              <label className="control">
                <span className="control-label">Confidence</span>
                <select value={confidenceFilter} onChange={(event) => setConfidenceFilter(event.target.value as ConfidenceFilter)}>
                  <option value="all">All confidence</option>
                  <option value="authoritative">Authoritative</option>
                  <option value="inferred">Inferred</option>
                  <option value="unverifiable">Unverifiable</option>
                </select>
              </label>
              <label className="control">
                <span className="control-label">Boundary</span>
                <select value={boundaryFilter} onChange={(event) => setBoundaryFilter(event.target.value as BoundaryFilter)}>
                  <option value="all">All boundaries</option>
                  <option value="guest">Guest</option>
                  <option value="guest-host interface">Guest-host interface</option>
                  <option value="host-unverifiable">Host-unverifiable</option>
                </select>
              </label>
            </div>

            <div className="toggle-row">
              <label className="toggle-card">
                <input type="checkbox" checked={showNewOnly} onChange={(event) => setShowNewOnly(event.target.checked)} />
                <div>
                  <span className="control-label">Focus mode</span>
                  <span>New since last scan</span>
                </div>
              </label>
              <label className="toggle-card">
                <input
                  type="checkbox"
                  checked={hideSuppressed}
                  onChange={(event) => setHideSuppressed(event.target.checked)}
                />
                <div>
                  <span className="control-label">Suppressed</span>
                  <span>Hide suppressed findings</span>
                </div>
              </label>
            </div>
          </div>

          <div className="queue-summary">
            <span>{filteredFindings.length} visible findings</span>
            <span>{visibleGroups.length} grouped issues</span>
            <span>{suppressions.length} active suppressions</span>
            <span>{showNewOnly ? "Showing only newly introduced items" : "Showing all matching findings"}</span>
          </div>

          {visibleGroups.length === 0 ? (
            <div className="empty">No findings match the current filters.</div>
          ) : (
            <div className="group-list">
              {visibleGroups.map((group) => (
                <section className="finding-group" key={group.id}>
                  <div className="group-head">
                    <div>
                      <h3>{group.title}</h3>
                      <p>{group.summary}</p>
                    </div>
                    <div className="badges">
                      <span className={`badge severity-${group.severity}`}>{group.severity}</span>
                      <span className={`badge confidence-${group.confidence}`}>{group.confidence}</span>
                      <span className="badge">{group.boundary}</span>
                      {group.newInLatest ? <span className="badge badge-hot">new</span> : null}
                    </div>
                  </div>

                  <div className="surface-list">
                    {group.impactedSurfaces.map((surface) => (
                      <span className="surface-chip" key={surface}>
                        {surface}
                      </span>
                    ))}
                  </div>

                  <div className="finding-stack">
                    {group.findingIds.map((findingId) => {
                      const finding = findingMap.get(findingId);
                      if (!finding) {
                        return null;
                      }
                      return (
                        <article className="finding-card" key={`${finding.id}-${finding.createdAt}`}>
                          <div className="finding-top">
                            <div>
                              <h4>{finding.title}</h4>
                              <p>{finding.summary}</p>
                            </div>
                            <div className="badges">
                              <span className={`badge severity-${finding.severity}`}>{finding.severity}</span>
                              <span className={`badge confidence-${finding.confidence}`}>{finding.confidence}</span>
                              <span className="badge">{finding.subcategory}</span>
                              {finding.suppressed ? <span className="badge badge-muted">suppressed</span> : null}
                            </div>
                          </div>

                          <div className="finding-grid finding-grid-dense">
                            <div className="finding-block">
                              <span className="subsection-label">Why this matters</span>
                              <p>{finding.rationale}</p>
                              <p className="block-note">{finding.operatorImpact}</p>
                            </div>
                            <div className="finding-block">
                              <span className="subsection-label">Certainty</span>
                              <p>{finding.certaintyReason}</p>
                              <p className="block-note">{finding.falsePositiveGuidance}</p>
                            </div>
                            <div className="finding-block">
                              <span className="subsection-label">What the guest cannot know</span>
                              <p>{finding.whyGuestCannotKnow ?? "This conclusion is already guest-authoritative; host-side uncertainty is not central to this finding."}</p>
                            </div>
                          </div>

                          <details className="details-block" open>
                            <summary>Evidence</summary>
                            <div className="details-grid">
                              {finding.evidence.map((item) => (
                                <div className="evidence-item" key={item.id}>
                                  <strong>{item.label}</strong>
                                  <div>{item.value}</div>
                                  <div className="meta">Source: {item.source}</div>
                                  <div className="meta">{item.pathOrCommand}</div>
                                  <div className="meta">{item.interpretation}</div>
                                </div>
                              ))}
                            </div>
                          </details>

                          <details className="details-block" open>
                            <summary>Analysis metadata</summary>
                            <div className="details-grid">
                              <div className="evidence-item">
                                <strong>Fingerprint</strong>
                                <div className="meta">{finding.fingerprint}</div>
                              </div>
                              <div className="evidence-item">
                                <strong>Rule</strong>
                                <div>{finding.ruleId}</div>
                                <div className="meta">{finding.certaintyReason}</div>
                              </div>
                              <div className="evidence-item">
                                <strong>Remediation preconditions</strong>
                                <div>
                                  {finding.remediationPreconditions.length > 0
                                    ? finding.remediationPreconditions.join(", ")
                                    : "No explicit preconditions recorded."}
                                </div>
                              </div>
                            </div>
                          </details>

                          {finding.remediation.length > 0 ? (
                            <details className="details-block" open>
                              <summary>Fix commands</summary>
                              <div className="details-grid">
                                {finding.remediation.map((action) => (
                                  <div className="evidence-item" key={action.id}>
                                    <strong>{action.title}</strong>
                                    <div>{action.description}</div>
                                    <div className="meta">{action.requiresRoot ? "Root required" : "No root required"}</div>
                                    {action.commands.map((command) => (
                                      <div className="command-shell" key={command}>
                                        <code>{command}</code>
                                        <button type="button" className="copy-button" onClick={() => copyCommand(command)}>
                                          {copiedCommand === command ? "Copied" : "Copy"}
                                        </button>
                                      </div>
                                    ))}
                                  </div>
                                ))}
                              </div>
                            </details>
                          ) : null}

                          {finding.suppressionEligible ? (
                            <div className="suppression-row">
                              <button
                                type="button"
                                className="copy-button"
                                onClick={() => createSuppressionForFinding(finding, "fingerprint")}
                                disabled={isPending || Boolean(finding.suppressed)}
                              >
                                Suppress this finding
                              </button>
                              <button
                                type="button"
                                className="copy-button"
                                onClick={() => createSuppressionForFinding(finding, "rule")}
                                disabled={isPending}
                              >
                                Suppress this rule
                              </button>
                              {finding.suppression ? <span className="meta">Reason: {finding.suppression.reason ?? "none"}</span> : null}
                            </div>
                          ) : null}
                        </article>
                      );
                    })}
                  </div>
                </section>
              ))}
            </div>
          )}
        </div>

        <aside className="console-side operations-rail">
          <div className="panel">
            <div className="panel-kicker">History</div>
            <h2>Recent scan deltas</h2>
            <div className="history-list">
              {history.length === 0 ? (
                <div className="empty">No stored history yet.</div>
              ) : (
                history.map((entry) => (
                  <div className="history-item" key={entry.scanId}>
                    <div className="history-topline">
                      <strong>{formatDate(entry.collectedAt)}</strong>
                      <span className={`history-score ${scoreClass(entry.overallScore)}`}>{entry.overallScore}/100</span>
                    </div>
                    <div className="meta">{entry.profile}</div>
                    <div className="delta-line">
                      <span>+{entry.newFindingCount}</span>
                      <span>-{entry.resolvedFindingCount}</span>
                      <span>~{entry.changedFindingCount}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="panel">
            <div className="panel-kicker">Method</div>
            <h2>Compare scans</h2>
            <div className="compare-controls">
              <label className="control">
                <span className="control-label">From</span>
                <select value={compareFrom ?? ""} onChange={(event) => setCompareFrom(event.target.value || null)}>
                  {history.map((entry) => (
                    <option key={`from-${entry.scanId}`} value={entry.scanId}>
                      {new Date(entry.collectedAt).toLocaleString()}
                    </option>
                  ))}
                </select>
              </label>
              <label className="control">
                <span className="control-label">To</span>
                <select value={compareTo ?? ""} onChange={(event) => setCompareTo(event.target.value || null)}>
                  {history.map((entry) => (
                    <option key={`to-${entry.scanId}`} value={entry.scanId}>
                      {new Date(entry.collectedAt).toLocaleString()}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="priority-list">
              <div className="priority-item">New: {comparison?.summary.newCount ?? 0}</div>
              <div className="priority-item">Resolved: {comparison?.summary.resolvedCount ?? 0}</div>
              <div className="priority-item">Changed: {comparison?.summary.changedCount ?? 0}</div>
              <div className="priority-item">Suppressed: {comparison?.summary.suppressedCount ?? 0}</div>
            </div>
            {comparisonSections.map((section) => (
              <details className="details-block" key={section.key}>
                <summary>{section.label}</summary>
                <div className="surface-list">
                  {section.ids.length > 0 ? (
                    section.ids.map((id) => (
                      <span className="surface-chip" key={`${section.key}-${id}`}>
                        {id}
                      </span>
                    ))
                  ) : (
                    <span className="meta">None</span>
                  )}
                </div>
              </details>
            ))}
          </div>

          <div className="panel">
            <div className="panel-kicker">Method</div>
            <h2>Trust boundary</h2>
            <div className="trust-stack">
              <div className="trust-line">
                <strong>Authoritative</strong>
                <span>Guest-visible state such as sockets, packages, services, mounts, firewall state, and local devices.</span>
              </div>
              <div className="trust-line">
                <strong>Inferred</strong>
                <span>Likely exposure or leakage paths derived from guest-visible integration surfaces and route context.</span>
              </div>
              <div className="trust-line">
                <strong>Unverifiable</strong>
                <span>Host libvirt, hypervisor launch policy, storage handling, and final escape resistance.</span>
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-kicker">Collection</div>
            <h2>Coverage and caveats</h2>
            <div className="priority-list">
              {(posture.environment?.collectionWarnings.length
                ? posture.environment.collectionWarnings
                : ["No collection warnings for the latest scan."]).map((item) => (
                <div className="priority-item" key={item}>
                  {item}
                </div>
              ))}
            </div>
          </div>

          <div className="panel">
            <div className="panel-kicker">Suppressions</div>
            <h2>Active local waivers</h2>
            <div className="priority-list">
              {suppressions.length === 0 ? (
                <div className="priority-item">No active suppressions.</div>
              ) : (
                suppressions.map((suppression) => (
                  <div className="priority-item suppression-item" key={suppression.id}>
                    <div>
                      <strong>{suppression.scope}</strong>
                      <div className="meta">{suppression.matchValue}</div>
                      <div className="meta">{suppression.reason ?? "No reason recorded."}</div>
                    </div>
                    <button
                      type="button"
                      className="copy-button"
                      onClick={() => removeSuppressionById(suppression.id)}
                      disabled={isPending}
                    >
                      Remove
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="panel">
            <div className="panel-kicker">Operator Notes</div>
            <h2>Top priorities</h2>
            <div className="priority-list">
              {(posture.posture?.topPriorities ?? ["Run a scan to generate top-priority findings."]).map((item) => (
                <div className="priority-item" key={item}>
                  {item}
                </div>
              ))}
            </div>
            <p className="meta">{posture.posture?.deltaHeadline ?? "No delta headline available yet."}</p>
          </div>
        </aside>
      </section>
    </main>
  );
}
