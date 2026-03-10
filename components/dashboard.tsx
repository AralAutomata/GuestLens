"use client";

import { useEffect, useState, useTransition } from "react";

import type { Finding, PostureSummary } from "@/lib/types";

interface HistoryEntry {
  scanId: string;
  collectedAt: string;
  overallScore: number;
  findingCount: number;
}

interface PostureResponse {
  posture: PostureSummary | null;
  scanId: string | null;
  collectedAt: string | null;
}

interface FindingsResponse {
  findings: Finding[];
}

interface HistoryResponse {
  history: HistoryEntry[];
}

function countBySeverity(findings: Finding[], severity: Finding["severity"]): number {
  return findings.filter((finding) => finding.severity === severity).length;
}

function countByBoundary(findings: Finding[], boundary: Finding["boundary"]): number {
  return findings.filter((finding) => finding.boundary === boundary).length;
}

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

export function Dashboard() {
  const [posture, setPosture] = useState<PostureResponse>({ posture: null, scanId: null, collectedAt: null });
  const [findings, setFindings] = useState<Finding[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  async function loadAll() {
    setError(null);
    const [postureResponse, findingsResponse, historyResponse] = await Promise.all([
      fetch("/api/posture", { cache: "no-store" }),
      fetch("/api/findings", { cache: "no-store" }),
      fetch("/api/history", { cache: "no-store" })
    ]);

    if (!postureResponse.ok) {
      throw new Error(await postureResponse.text());
    }
    if (!findingsResponse.ok) {
      throw new Error(await findingsResponse.text());
    }
    if (!historyResponse.ok) {
      throw new Error(await historyResponse.text());
    }

    const postureJson = (await postureResponse.json()) as PostureResponse;
    const findingsJson = (await findingsResponse.json()) as FindingsResponse;
    const historyJson = (await historyResponse.json()) as HistoryResponse;
    setPosture(postureJson);
    setFindings(findingsJson.findings);
    setHistory(historyJson.history);
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

  useEffect(() => {
    loadAll().catch((caught) => {
      setError(caught instanceof Error ? caught.message : "Failed to load dashboard.");
    });
  }, []);

  const criticalCount = countBySeverity(findings, "critical");
  const highCount = countBySeverity(findings, "high");
  const mediumCount = countBySeverity(findings, "medium");
  const hostBlindSpots = countByBoundary(findings, "host-unverifiable");
  const interfaceFindings = countByBoundary(findings, "guest-host interface");

  return (
    <main className="shell">
      <section className="hero-grid">
        <div className="hero hero-panel">
          <p className="eyebrow">Host0 &lt;= Virt-Manager =&gt; Guest</p>
          <h1>InsideJobVM</h1>
          <p>
            Guest-resident hardening analytics for Linux KVM systems. The dashboard separates what the VM can prove,
            what it can only infer about host-guest exposure, and what remains outside the guest trust boundary.
          </p>
          <div className="toolbar">
            <button className="button" onClick={runScan} disabled={isPending}>
              {isPending ? "Scanning..." : "Run guest scan"}
            </button>
            <span className="meta">Latest scan: {formatDate(posture.collectedAt)}</span>
          </div>
          <div className="hero-tags">
            <span className="badge">guest-only telemetry</span>
            <span className="badge">localhost UI</span>
            <span className="badge">manual fixes only</span>
          </div>
          {error ? <div className="error">{error}</div> : null}
        </div>

        <div className="panel posture-hero">
          <div className="panel-kicker">Overall Posture</div>
          <div className={`hero-score ${scoreClass(posture.posture?.overallScore ?? 0)}`}>
            {posture.posture ? `${posture.posture.overallScore}/100` : "--"}
          </div>
          <p>
            {posture.posture
              ? posture.posture.trustStatement
              : "Run the first scan to generate posture scoring across hardening, exposure, leakage, remediation readiness, and host blind spots."}
          </p>
          <div className="mini-stats">
            <div className="mini-stat">
              <span className="mini-label">Findings</span>
              <strong>{findings.length}</strong>
            </div>
            <div className="mini-stat">
              <span className="mini-label">Interface risk</span>
              <strong>{interfaceFindings}</strong>
            </div>
            <div className="mini-stat">
              <span className="mini-label">Blind spots</span>
              <strong>{hostBlindSpots}</strong>
            </div>
          </div>
        </div>
      </section>

      <section className="metric-strip">
        <div className="metric-card metric-card-danger">
          <span className="metric-label">Critical + High</span>
          <strong>{criticalCount + highCount}</strong>
          <p>Findings that should drive the next remediation cycle.</p>
        </div>
        <div className="metric-card metric-card-warn">
          <span className="metric-label">Medium</span>
          <strong>{mediumCount}</strong>
          <p>Issues that widen exposure or create drift from a hardened baseline.</p>
        </div>
        <div className="metric-card metric-card-accent">
          <span className="metric-label">Host Interface</span>
          <strong>{interfaceFindings}</strong>
          <p>Signals involving guest-host integration paths or likely crossover surfaces.</p>
        </div>
        <div className="metric-card">
          <span className="metric-label">Scan ID</span>
          <strong>{posture.scanId ? `${posture.scanId.slice(0, 8)}...` : "n/a"}</strong>
          <p>Current stored baseline used by the findings and posture views.</p>
        </div>
      </section>

      <section className="grid score-grid">
        {posture.posture ? (
          posture.posture.scores.map((score) => (
            <div className="panel score-card" key={score.category}>
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

      <section className="support-grid">
        <div className="panel">
            <div className="section-head">
              <div>
                <div className="panel-kicker">Operational View</div>
                <h2>History</h2>
              </div>
            </div>
            {history.length === 0 ? (
              <div className="empty">No historical scans stored yet.</div>
            ) : (
              <div className="history-list">
                {history.map((entry) => (
                  <div className="history-item" key={entry.scanId}>
                    <div className="history-topline">
                      <strong>{formatDate(entry.collectedAt)}</strong>
                      <span className={`history-score ${scoreClass(entry.overallScore)}`}>{entry.overallScore}/100</span>
                    </div>
                    <div className="meta">Findings: {entry.findingCount}</div>
                    <div className="meta">Scan: {entry.scanId.slice(0, 12)}...</div>
                  </div>
                ))}
              </div>
            )}
          </div>

        <div className="panel">
            <div className="section-head">
              <div>
                <div className="panel-kicker">Methodology</div>
                <h2>Trust Boundary</h2>
              </div>
            </div>
            <div className="trust-note trust-stack">
              <div className="trust-line">
                <strong>Authoritative</strong>
                <span>Guest OS state, services, mounts, packages, firewall, sockets, and visible virtual devices.</span>
              </div>
              <div className="trust-line">
                <strong>Inferred</strong>
                <span>Likely host-guest accessibility and leakage paths derived from guest-visible integration surfaces.</span>
              </div>
              <div className="trust-line">
                <strong>Unverifiable</strong>
                <span>libvirt XML, host firewalling, storage policy, MAC labels, and hypervisor escape resistance.</span>
              </div>
            </div>
        </div>

        <div className="panel">
            <div className="section-head">
              <div>
                <div className="panel-kicker">Fix Workflow</div>
                <h2>Manual by Design</h2>
              </div>
            </div>
            <p>
              InsideJobVM is deliberately read-only in the browser. The UI gives you analytics, rationale, and fix
              commands, but privileged changes stay in the guest shell under your control.
            </p>
            <div className="callout-grid">
              <div className="callout">
                <strong>Why</strong>
                <span>Web-triggered remediation inside the guest adds complexity without improving trust.</span>
              </div>
              <div className="callout">
                <strong>How</strong>
                <span>Review each finding, copy the command, run it with `sudo` if needed, then rescan.</span>
              </div>
            </div>
        </div>
      </section>

      <section className="panel panel-main">
        <div className="section-head">
          <div>
            <div className="panel-kicker">Primary Queue</div>
            <h2>Findings</h2>
          </div>
          <p className="section-copy">
            Recommendations are advisory only. Review the evidence, then run the proposed commands manually in the
            guest terminal when appropriate.
          </p>
        </div>
        {findings.length === 0 ? (
          <div className="empty">No stored findings yet. Run a scan to collect guest state.</div>
        ) : (
          <div className="finding-list">
            {findings.map((finding) => (
              <article className="finding finding-wide" key={`${finding.id}-${finding.createdAt}`}>
                <div className="finding-head">
                  <div className="finding-summary">
                    <h3>{finding.title}</h3>
                    <p>{finding.summary}</p>
                  </div>
                  <div className="badges">
                    <span className={`badge severity-${finding.severity}`}>{finding.severity}</span>
                    <span className={`badge confidence-${finding.confidence}`}>{finding.confidence}</span>
                    <span className="badge">{finding.boundary}</span>
                  </div>
                </div>
                <div className={`finding-body ${finding.remediation.length > 0 ? "finding-body-has-fix" : ""}`}>
                  <div className="finding-column">
                    <div className="subsection-label">Evidence</div>
                    <div className="evidence-list evidence-grid">
                      {finding.evidence.map((item) => (
                        <div className="evidence-item" key={item.id}>
                          <strong>{item.label}</strong>
                          <div>{item.detail}</div>
                          <div className="meta">Source: {item.source}</div>
                        </div>
                      ))}
                    </div>
                    <div className="footer-note">{finding.rationale}</div>
                  </div>
                  {finding.remediation.length > 0 ? (
                    <div className="finding-column finding-column-fix">
                      <div className="subsection-label">Fix Guidance</div>
                      <div className="finding-actions">
                        {finding.remediation.map((action) => (
                          <div className="evidence-item" key={action.id}>
                            <strong>{action.title}</strong>
                            <div className="meta">{action.description}</div>
                            <div className="meta">
                              {action.mode === "command"
                                ? "Run these commands manually in the guest terminal."
                                : "Follow the manual guidance below in the guest terminal or config files."}
                            </div>
                            <div className="command-list">
                              {action.commands.map((command) => (
                                <div className="command-item" key={command}>
                                  {command}
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}
