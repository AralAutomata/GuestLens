"use client";

import { useEffect, useState, useTransition } from "react";

import type { Finding, FindingGroup, PolicyProfile, PolicyProfileDefinition, PostureSummary, ScanDelta } from "@/lib/types";

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
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  async function loadAll() {
    setError(null);
    const [postureResponse, findingsResponse, historyResponse, profilesResponse] = await Promise.all([
      fetch("/api/posture", { cache: "no-store" }),
      fetch("/api/findings", { cache: "no-store" }),
      fetch("/api/history", { cache: "no-store" }),
      fetch("/api/profiles", { cache: "no-store" })
    ]);

    if (!postureResponse.ok || !findingsResponse.ok || !historyResponse.ok || !profilesResponse.ok) {
      throw new Error("Failed to load one or more dashboard resources.");
    }

    setPosture((await postureResponse.json()) as PostureResponse);
    setFindings((await findingsResponse.json()) as FindingsResponse);
    setHistory(((await historyResponse.json()) as HistoryResponse).history);
    setProfileState((await profilesResponse.json()) as ProfilesResponse);
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

  useEffect(() => {
    loadAll().catch((caught) => {
      setError(caught instanceof Error ? caught.message : "Failed to load dashboard.");
    });
  }, []);

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

  return (
    <main className="shell">
      <section className="topbar">
        <div className="topbar-copy">
          <p className="eyebrow">HostGuard Linux</p>
          <h1>Security posture dashboard</h1>
          <p className="topbar-text">
            Review guest-visible exposure, understand confidence boundaries, and move directly into validated
            remediation steps.
          </p>
        </div>

        <div className="topbar-meta">
          <span className="status-chip">Guest-visible evidence</span>
          <span className="meta">Last updated {formatDate(posture.collectedAt)}</span>
        </div>
      </section>

      <section className="hero-grid">
        <div className="hero-panel hero-shell">
          <div className="hero-copy">
            <p className="eyebrow">Workspace Overview</p>
            <h2 className="hero-title">Faster review flow for findings, trust boundaries, and next actions.</h2>
            <p className="hero-text">
              The dashboard keeps posture, findings, remediation commands, and scan history in one place so
              operators can prioritize quickly without losing the evidence behind each decision.
            </p>
          </div>

          <div className="hero-actions">
            <button className="button" onClick={runScan} disabled={isPending}>
              {isPending ? "Scanning..." : "Run guest scan"}
            </button>
            <a
              className="button button-ghost"
              href={posture.scanId ? `/api/export?scanId=${posture.scanId}&format=json` : "#"}
            >
              Export sanitized report
            </a>
            <span className="meta">Profile: {activeProfile?.label ?? "Balanced"}</span>
          </div>

          <div className="hero-highlights">
            <div className="highlight-card">
              <span className="mini-label">Latest scan</span>
              <strong>{formatDate(posture.collectedAt)}</strong>
            </div>
            <div className="highlight-card">
              <span className="mini-label">Active profile</span>
              <strong>{activeProfile?.label ?? "Balanced"}</strong>
              <span>{activeProfile?.emphasis ?? "Balanced coverage for day-to-day review."}</span>
            </div>
            <div className="highlight-card">
              <span className="mini-label">Current delta</span>
              <strong>{posture.delta?.summary.newCount ?? findings.findings.length} new items</strong>
              <span>{deltaSummary(findings.delta)}</span>
            </div>
          </div>
          {error ? <div className="error">{error}</div> : null}
        </div>

        <div className="hero-stack">
          <div className="panel posture-panel">
            <div className="panel-kicker">Current Posture</div>
            <div className={`hero-score ${scoreClass(posture.posture?.overallScore ?? 0)}`}>
              {posture.posture ? `${posture.posture.overallScore}/100` : "--"}
            </div>
            <p>{posture.posture?.trustStatement ?? "Run a scan to generate profile-aware posture scoring."}</p>
            <div className="mini-grid">
              <div className="mini-card">
                <span className="mini-label">Profile</span>
                <strong>{activeProfile?.label ?? "Balanced"}</strong>
              </div>
              <div className="mini-card">
                <span className="mini-label">Findings</span>
                <strong>{findings.findings.length}</strong>
              </div>
              <div className="mini-card">
                <span className="mini-label">Delta</span>
                <strong>{posture.delta?.summary.newCount ?? findings.findings.length}</strong>
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-kicker">Policy Profile</div>
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

      <section className="ops-grid">
        <div className="panel ops-card ops-card-danger">
          <div className="panel-kicker">Scan</div>
          <h2>Immediate Work</h2>
          <strong>{criticalCount + highCount}</strong>
          <p>Critical and high findings currently in the filtered queue.</p>
        </div>
        <div className="panel ops-card ops-card-warn">
          <div className="panel-kicker">Understand</div>
          <h2>Delta Since Last Scan</h2>
          <strong>{deltaSummary(findings.delta)}</strong>
          <p>Use new and changed findings as the default review path.</p>
        </div>
        <div className="panel ops-card ops-card-accent">
          <div className="panel-kicker">Fix</div>
          <h2>Manual Commands</h2>
          <strong>{mediumCount}</strong>
          <p>Medium findings still matter when they widen exposure or leak data across trust boundaries.</p>
        </div>
      </section>

      <section className="score-grid">
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
      </section>

      <section className="console-grid">
        <div className="panel console-main">
          <div className="section-head">
            <div>
              <div className="panel-kicker">Queue</div>
              <h2>Findings queue</h2>
            </div>
            <p className="section-copy">
              Filter first, then review the grouped evidence. Confidence and trust-boundary limits stay visible
              throughout the remediation flow.
            </p>
          </div>

          <div className="filter-toolbar">
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
            <label className="toggle-card">
              <input type="checkbox" checked={showNewOnly} onChange={(event) => setShowNewOnly(event.target.checked)} />
              <div>
                <span className="control-label">Focus mode</span>
                <span>New since last scan</span>
              </div>
            </label>
          </div>

          <div className="queue-summary">
            <span>{filteredFindings.length} visible findings</span>
            <span>{visibleGroups.length} grouped issues</span>
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
                            </div>
                          </div>

                          <div className="finding-grid">
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

                          <details className="details-block">
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
                        </article>
                      );
                    })}
                  </div>
                </section>
              ))}
            </div>
          )}
        </div>

        <aside className="console-side">
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
