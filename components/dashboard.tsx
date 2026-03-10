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

  return (
    <main className="shell">
      <section className="hero">
        <p className="eyebrow">Host0 &lt;= Virt-Manager =&gt; Guest</p>
        <h1>InsideJobVM</h1>
        <p>
          A guest-resident analyzer for Linux KVM systems. It can certify guest state, infer host-guest exposure, and
          clearly mark host controls that cannot be proven from inside the VM.
        </p>
        <div className="toolbar">
          <button className="button" onClick={runScan} disabled={isPending}>
            {isPending ? "Scanning..." : "Run guest scan"}
          </button>
          <span className="meta">Latest scan: {formatDate(posture.collectedAt)}</span>
        </div>
        {error ? <div className="error">{error}</div> : null}
      </section>

      <section className="grid top-grid">
        <div className="panel">
          <h2>Trust boundary</h2>
          <p>
            This dashboard intentionally separates authoritative guest facts from inferred exposure and unverifiable
            host controls. It does not claim to certify hypervisor isolation from inside the guest.
          </p>
          <div className="trust-note">
            {posture.posture ? (
              <>
                <div className={`score-value ${scoreClass(posture.posture.overallScore)}`}>{posture.posture.overallScore}/100</div>
                <p>{posture.posture.trustStatement}</p>
              </>
            ) : (
              <p>No posture summary is available until the first scan completes.</p>
            )}
          </div>
        </div>

        <div className="panel">
          <h2>Fix workflow</h2>
          <div className="status-line">
            <span>Scan ID: {posture.scanId ?? "n/a"}</span>
            <span>Findings: {findings.length}</span>
          </div>
          <div className="trust-note">
            <h3>Manual by design</h3>
            <p>
              InsideJobVM does not execute remediations from the web UI. Findings include suggested commands and manual
              steps that you review and run yourself in the guest terminal.
            </p>
          </div>
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

      <section className="two-col">
        <div className="panel">
          <h2>Findings</h2>
          {findings.length === 0 ? (
            <div className="empty">No stored findings yet. Run a scan to collect guest state.</div>
          ) : (
            <div className="finding-list">
              {findings.map((finding) => (
                <article className="finding" key={`${finding.id}-${finding.createdAt}`}>
                  <div className="finding-head">
                    <div>
                      <h3>{finding.title}</h3>
                      <p>{finding.summary}</p>
                    </div>
                    <div className="badges">
                      <span className={`badge severity-${finding.severity}`}>{finding.severity}</span>
                      <span className={`badge confidence-${finding.confidence}`}>{finding.confidence}</span>
                      <span className="badge">{finding.boundary}</span>
                    </div>
                  </div>
                  <div className="evidence-list">
                    {finding.evidence.map((item) => (
                      <div className="evidence-item" key={item.id}>
                        <strong>{item.label}</strong>
                        <div>{item.detail}</div>
                        <div className="meta">Source: {item.source}</div>
                      </div>
                    ))}
                  </div>
                  <div className="footer-note">{finding.rationale}</div>
                  {finding.remediation.length > 0 ? (
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
                  ) : null}
                </article>
              ))}
            </div>
          )}
        </div>

        <div className="grid">
          <div className="panel">
            <h2>History</h2>
            {history.length === 0 ? (
              <div className="empty">No historical scans stored yet.</div>
            ) : (
              <div className="history-list">
                {history.map((entry) => (
                  <div className="history-item" key={entry.scanId}>
                    <strong>{formatDate(entry.collectedAt)}</strong>
                    <div className="meta">Score: {entry.overallScore}/100</div>
                    <div className="meta">Findings: {entry.findingCount}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="panel">
            <h2>Visibility limits</h2>
            <p>
              The guest cannot inspect libvirt XML, host firewalling, host storage permissions, host MAC labels, or
              DMA/IOMMU posture. Those items are intentionally tracked as unverifiable rather than guessed.
            </p>
            <div className="footer-note">
              Use a separate host-side collector later if you need verified host and hypervisor posture.
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
