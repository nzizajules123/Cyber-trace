import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { SeverityBadge, formatDate, formatLabel } from "./CaseFormFields.jsx";
import Icon from "./Icon.jsx";
import WorkspaceLayout from "./WorkspaceLayout.jsx";
import { getCases } from "../services/casesApi.js";
import {
  analyzeEvidence,
  getEvidenceList,
  getExtractedIocs,
  getFindings,
  getForensicEvents,
  getUnifiedTimeline,
  reviewFinding,
} from "../services/forensicsApi.js";

const FINDING_STATUSES = ["REQUIRES_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "MITIGATED"];

export function LogAnalysisPage() {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [evidenceItems, setEvidenceItems] = useState([]);
  const [selectedEvidence, setSelectedEvidence] = useState("");
  const [caseFilter, setCaseFilter] = useState("");
  const [query, setQuery] = useState("");
  const [events, setEvents] = useState([]);
  const [iocs, setIocs] = useState([]);
  const [lastRun, setLastRun] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getCases({ page: 1, size: 100, signal: controller.signal }),
      getEvidenceList({ caseId: caseFilter, signal: controller.signal }),
      getForensicEvents({ caseId: caseFilter, query, signal: controller.signal }),
      getExtractedIocs({ caseId: caseFilter, signal: controller.signal }),
    ])
      .then(([casesRes, evRes, eventsRes, iocsRes]) => {
        setCases(casesRes.items);
        setEvidenceItems(evRes.items);
        setEvents(eventsRes.items);
        setIocs(iocsRes.items);
        if (!selectedEvidence && evRes.items[0]) {
          setSelectedEvidence(evRes.items[0].evidenceCode);
        }
      })
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Failed to load analysis data.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [caseFilter, query, reloadKey]);

  const handleRunAnalysis = async () => {
    if (!selectedEvidence) return;
    setAnalyzing(true);
    setError("");
    try {
      const res = await analyzeEvidence(selectedEvidence);
      setLastRun(res);
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Analysis failed.");
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : error ? "unavailable" : "live"}
      cases={cases}
      pageTitle="Log Analysis"
      query={query}
      onQueryChange={setQuery}
      onSelectCase={(c) => c && navigate(`/cases/${encodeURIComponent(c)}`)}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> AUTOMATED LOG & IOC ENGINE</span>
          <h1>Log Analysis & IOC Extraction</h1>
          <p>Parse JSONL, CSV, Syslog/SSH, and Apache/Nginx logs into structured forensic events, IOCs, and automated findings.</p>
        </div>
        <Link className="secondary-button" to="/analysis/findings">
          View Findings
        </Link>
      </div>

      {error && (
        <div className="dashboard-error" role="alert">
          <Icon name="findings" size={18} />
          <div><strong>Analysis error</strong><p>{error}</p></div>
        </div>
      )}

      <section className="panel analysis-runner-panel">
        <div className="analysis-runner-row">
          <label className="analysis-runner-select">
            <span>Select ingested evidence file to analyze</span>
            <select value={selectedEvidence} onChange={(e) => setSelectedEvidence(e.target.value)}>
              {evidenceItems.length === 0 ? (
                <option value="">No evidence files ingested yet</option>
              ) : (
                evidenceItems.map((ev) => (
                  <option key={ev.evidenceCode} value={ev.evidenceCode}>
                    {ev.evidenceCode} — {ev.originalFilename} ({ev.caseNumber})
                  </option>
                ))
              )}
            </select>
          </label>
          <button
            className="primary-button"
            type="button"
            onClick={handleRunAnalysis}
            disabled={analyzing || !selectedEvidence}
          >
            {analyzing ? "Parsing & Correlating…" : "Run Automated Analysis"}
          </button>
        </div>
        {lastRun && (
          <div className="case-success-notice" role="status">
            Analyzed <strong>{lastRun.evidenceCode}</strong> (format: <code>{lastRun.detectedFormat}</code>) —{" "}
            <strong>{lastRun.eventsParsed}</strong> events parsed, <strong>{lastRun.uniqueIocs}</strong> unique IOCs,{" "}
            <strong>{lastRun.findingsGenerated}</strong> analytical findings generated.
          </div>
        )}
      </section>

      <section className="panel case-detail-panel">
        <div className="case-list-toolbar">
          <div>
            <h2>Extracted Indicators of Compromise ({iocs.length})</h2>
            <p>IPv4 addresses, emails, URLs, CVEs, SHA-256 and MD5 hashes extracted from parsed logs.</p>
          </div>
          <label className="filter-control">
            <span className="sr-only">Filter by case</span>
            <select value={caseFilter} onChange={(e) => setCaseFilter(e.target.value)} aria-label="Filter by case">
              <option value="">All cases</option>
              {cases.map((c) => <option key={c.caseNumber} value={c.caseNumber}>{c.caseNumber}</option>)}
            </select>
          </label>
        </div>
        {iocs.length === 0 ? (
          <p className="forensic-submeta">No IOCs extracted yet. Run analysis on an ingested log file above.</p>
        ) : (
          <div className="ioc-chip-grid">
            {iocs.map((ioc) => (
              <span className={`ioc-chip ioc-${ioc.type.toLowerCase().replace(/[^a-z0-9]/g, "")}`} key={`${ioc.type}:${ioc.value}`}>
                <small>{ioc.type}</small>
                <code>{ioc.value}</code>
                <b>×{ioc.count}</b>
              </span>
            ))}
          </div>
        )}
      </section>

      <section className="panel case-list-panel">
        <div className="case-list-toolbar">
          <div>
            <h2>Parsed forensic events ({events.length})</h2>
            <p>Normalized recorded facts extracted directly from source evidence files.</p>
          </div>
        </div>
        {loading ? (
          <div className="case-loading">Loading parsed events…</div>
        ) : events.length === 0 ? (
          <div className="case-empty">
            <strong>No parsed events yet</strong>
            <p>Upload a log file in Evidence Repository and click &quot;Run Automated Analysis&quot;.</p>
          </div>
        ) : (
          <div className="table-scroll case-list-table-wrap">
            <table className="cases-table">
              <thead>
                <tr>
                  <th scope="col">TIMESTAMP</th>
                  <th scope="col">TYPE</th>
                  <th scope="col">SOURCE IP</th>
                  <th scope="col">USER</th>
                  <th scope="col">DESCRIPTION</th>
                  <th scope="col">SOURCE</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.id}>
                    <td>{formatDate(ev.occurredAt, true)}</td>
                    <td>
                      <span className="event-type">{ev.eventType}</span>
                      <div className="forensic-submeta">{ev.category}</div>
                    </td>
                    <td><code>{ev.sourceIp || "—"}</code></td>
                    <td>{ev.username || "—"}</td>
                    <td>{ev.description}</td>
                    <td><span className="case-id">{ev.evidenceCode}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </WorkspaceLayout>
  );
}

export function ForensicFindingsPage() {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [findings, setFindings] = useState([]);
  const [statusFilter, setStatusFilter] = useState("");
  const [caseFilter, setCaseFilter] = useState("");
  const [notesById, setNotesById] = useState({});
  const [savingId, setSavingId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getCases({ page: 1, size: 100, signal: controller.signal }),
      getFindings({ caseId: caseFilter, status: statusFilter, signal: controller.signal }),
    ])
      .then(([casesRes, findRes]) => {
        setCases(casesRes.items);
        setFindings(findRes.items);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Failed to load findings.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [caseFilter, statusFilter, reloadKey]);

  const handleReview = async (findingId, nextStatus) => {
    setSavingId(findingId);
    setError("");
    try {
      const updated = await reviewFinding(findingId, {
        status: nextStatus,
        reviewerNotes: notesById[findingId] ?? "",
      });
      setNotice(`Finding "${updated.title}" marked as ${formatLabel(updated.status)}.`);
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to update finding.");
    } finally {
      setSavingId(null);
    }
  };

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : error ? "unavailable" : "live"}
      cases={cases}
      pageTitle="Forensic Findings"
      showSearch={false}
      onSelectCase={(c) => c && navigate(`/cases/${encodeURIComponent(c)}`)}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> DETECTION & TRIAGE</span>
          <h1>Forensic Findings</h1>
          <p>Analytical detections generated by correlation rules — kept distinct from raw recorded facts.</p>
        </div>
        <div className="case-list-controls">
          <label className="filter-control">
            <select value={caseFilter} onChange={(e) => setCaseFilter(e.target.value)} aria-label="Filter by case">
              <option value="">All cases</option>
              {cases.map((c) => <option key={c.caseNumber} value={c.caseNumber}>{c.caseNumber}</option>)}
            </select>
          </label>
          <label className="filter-control">
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Filter by status">
              <option value="">All statuses</option>
              {FINDING_STATUSES.map((s) => <option key={s} value={s}>{formatLabel(s)}</option>)}
            </select>
          </label>
        </div>
      </div>

      {notice && <div className="case-success-notice" role="status">{notice}</div>}
      {error && <div className="dashboard-error" role="alert"><Icon name="findings" size={18} /><div><strong>Error</strong><p>{error}</p></div></div>}

      {loading ? (
        <div className="case-loading">Loading analytical findings…</div>
      ) : findings.length === 0 ? (
        <section className="panel case-empty">
          <span className="empty-state-mark"><Icon name="findings" size={18} /></span>
          <strong>No analytical findings found</strong>
          <p>Run automated log analysis on ingested evidence to detect brute-force bursts, credential compromise, SQLi, and more.</p>
          <Link className="secondary-button" to="/analysis/log-analysis">Open Log Analysis</Link>
        </section>
      ) : (
        <div className="findings-stack">
          {findings.map((finding) => (
            <article className="panel finding-card" key={finding.id}>
              <div className="finding-card-header">
                <div>
                  <div className="finding-badges">
                    <SeverityBadge severity={finding.severity} />
                    <span className="record-kind record-finding">Analytical finding</span>
                    <span className="analysis-status">{formatLabel(finding.status)}</span>
                    <span className="forensic-submeta">Confidence: {formatLabel(finding.confidence)} · {finding.eventCount} events</span>
                  </div>
                  <h3>{finding.title}</h3>
                </div>
                <Link className="case-id case-title-link" to={`/cases/${encodeURIComponent(finding.caseNumber)}`}>
                  {finding.caseNumber}
                </Link>
              </div>
              <p className="finding-summary">{finding.summary}</p>
              {finding.indicators?.length > 0 && (
                <div className="ioc-chip-grid">
                  {finding.indicators.map((ind, idx) => (
                    <span className="ioc-chip" key={idx}>
                      <small>{ind.type}</small>
                      <code>{ind.value}</code>
                    </span>
                  ))}
                </div>
              )}
              <div className="finding-review-bar">
                <input
                  type="text"
                  placeholder="Add investigator review notes…"
                  value={notesById[finding.id] ?? finding.reviewerNotes ?? ""}
                  onChange={(e) => setNotesById((prev) => ({ ...prev, [finding.id]: e.target.value }))}
                />
                <div className="finding-review-actions">
                  <button
                    className="primary-button"
                    type="button"
                    disabled={savingId === finding.id}
                    onClick={() => handleReview(finding.id, "CONFIRMED")}
                  >
                    Confirm
                  </button>
                  <button
                    className="secondary-button"
                    type="button"
                    disabled={savingId === finding.id}
                    onClick={() => handleReview(finding.id, "MITIGATED")}
                  >
                    Mitigated
                  </button>
                  <button
                    className="secondary-button"
                    type="button"
                    disabled={savingId === finding.id}
                    onClick={() => handleReview(finding.id, "FALSE_POSITIVE")}
                  >
                    False Positive
                  </button>
                </div>
              </div>
            </article>
          ))}
        </div>
      )}
    </WorkspaceLayout>
  );
}

export function CaseTimelinePage() {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [caseFilter, setCaseFilter] = useState("");
  const [kindFilter, setKindFilter] = useState("ALL");
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getCases({ page: 1, size: 100, signal: controller.signal }),
      getUnifiedTimeline({ caseId: caseFilter, signal: controller.signal }),
    ])
      .then(([casesRes, timeRes]) => {
        setCases(casesRes.items);
        setItems(timeRes.items);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Failed to load timeline.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [caseFilter]);

  const visible = kindFilter === "ALL" ? items : items.filter((i) => i.sourceKind === kindFilter);

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : error ? "unavailable" : "live"}
      cases={cases}
      pageTitle="Case Timeline"
      showSearch={false}
      onSelectCase={(c) => c && navigate(`/cases/${encodeURIComponent(c)}`)}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> CHRONOLOGICAL RECONSTRUCTION</span>
          <h1>Unified Case Timeline</h1>
          <p>Correlated chronology combining recorded log facts, analytical findings, and case audit trails.</p>
        </div>
        <div className="case-list-controls">
          <label className="filter-control">
            <select value={caseFilter} onChange={(e) => setCaseFilter(e.target.value)} aria-label="Filter timeline by case">
              <option value="">All cases</option>
              {cases.map((c) => <option key={c.caseNumber} value={c.caseNumber}>{c.caseNumber}</option>)}
            </select>
          </label>
          <label className="filter-control">
            <select value={kindFilter} onChange={(e) => setKindFilter(e.target.value)} aria-label="Filter timeline by source">
              <option value="ALL">All sources</option>
              <option value="FINDING">Analytical findings</option>
              <option value="LOG_EVENT">Parsed log events</option>
              <option value="AUDIT">Case audit logs</option>
            </select>
          </label>
        </div>
      </div>

      {error && <div className="dashboard-error" role="alert"><Icon name="findings" size={18} /><div><strong>Error</strong><p>{error}</p></div></div>}

      <section className="panel timeline-panel">
        {loading ? (
          <div className="case-loading">Reconstructing timeline…</div>
        ) : visible.length === 0 ? (
          <div className="case-empty">
            <strong>No timeline entries yet</strong>
            <p>Create cases, ingest evidence, and run log analysis to populate the forensic timeline.</p>
          </div>
        ) : (
          <div className="timeline-list">
            {visible.map((entry) => (
              <article className="timeline-event" key={entry.id}>
                <span className={`timeline-marker${entry.recordType === "Analytical finding" ? " marker-finding" : ""}`} />
                <div className="timeline-event-main">
                  <div className="timeline-event-heading">
                    <span className="event-type">{entry.eventType}</span>
                    <span className={`record-kind${entry.recordType === "Analytical finding" ? " record-finding" : ""}`}>
                      {entry.recordType}
                    </span>
                    {entry.severity && <SeverityBadge severity={entry.severity} />}
                  </div>
                  <p><strong>{entry.title}</strong> — {entry.description}</p>
                  <div className="event-metadata">
                    <span><Icon name="evidence" size={13} />{entry.sourceRef}</span>
                    <span><Icon name="cases" size={13} />{entry.caseNumber}</span>
                    {entry.status && <span className="analysis-status">{formatLabel(entry.status)}</span>}
                  </div>
                </div>
                <time dateTime={entry.occurredAt}>{formatDate(entry.occurredAt, true)}</time>
              </article>
            ))}
          </div>
        )}
      </section>
    </WorkspaceLayout>
  );
}
