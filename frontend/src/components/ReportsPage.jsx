import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { SeverityBadge, StatusBadge, formatDate } from "./CaseFormFields.jsx";
import Icon from "./Icon.jsx";
import WorkspaceLayout from "./WorkspaceLayout.jsx";
import { getCases } from "../services/casesApi.js";
import { downloadCaseReportPdf, getCaseReportJson } from "../services/forensicsApi.js";

export default function ReportsPage() {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState("");
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    getCases({ page: 1, size: 100, signal: controller.signal })
      .then((res) => {
        setCases(res.items);
        if (res.items[0]) setSelectedCase(res.items[0].caseNumber);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Failed to load cases.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!selectedCase) {
      setPreview(null);
      return undefined;
    }
    const controller = new AbortController();
    setLoadingPreview(true);
    setError("");
    getCaseReportJson(selectedCase, { signal: controller.signal })
      .then(setPreview)
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Failed to preview report.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoadingPreview(false);
      });
    return () => controller.abort();
  }, [selectedCase]);

  const handleDownloadPdf = async () => {
    if (!selectedCase) return;
    setDownloading(true);
    setError("");
    try {
      await downloadCaseReportPdf(selectedCase);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "PDF download failed.");
    } finally {
      setDownloading(false);
    }
  };

  const handleDownloadJson = () => {
    if (!preview) return;
    const blob = new Blob([JSON.stringify(preview, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `CyberTrace_Report_${selectedCase}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : error ? "unavailable" : "live"}
      cases={cases}
      selectedCaseId={selectedCase}
      onSelectCase={(c) => c && navigate(`/cases/${encodeURIComponent(c)}`)}
      pageTitle="Reports"
      showSearch={false}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> FORENSIC REPORTING</span>
          <h1>Forensic Investigation Reports</h1>
          <p>Export court-ready PDF dossiers or JSON bundles distinguishing facts, analytical observations, methodology, and limitations.</p>
        </div>
      </div>

      {error && <div className="dashboard-error" role="alert"><Icon name="findings" size={18} /><div><strong>Report error</strong><p>{error}</p></div></div>}

      <section className="panel analysis-runner-panel">
        <div className="analysis-runner-row">
          <label className="analysis-runner-select">
            <span>Select investigation case</span>
            <select value={selectedCase} onChange={(e) => setSelectedCase(e.target.value)}>
              {cases.length === 0 ? (
                <option value="">No cases available</option>
              ) : (
                cases.map((c) => (
                  <option key={c.caseNumber} value={c.caseNumber}>
                    {c.caseNumber} — {c.title}
                  </option>
                ))
              )}
            </select>
          </label>
          {selectedCase && (
            <div className="case-detail-header-actions">
              <button
                className="primary-button"
                type="button"
                onClick={handleDownloadPdf}
                disabled={downloading}
              >
                <Icon name="reports" size={15} /> {downloading ? "Generating PDF…" : "Download PDF Report"}
              </button>
              <button className="secondary-button" type="button" onClick={handleDownloadJson} disabled={!preview}>
                Export JSON Bundle
              </button>
            </div>
          )}
        </div>
      </section>

      {loadingPreview ? (
        <div className="case-loading">Compiling report preview…</div>
      ) : preview && (
        <section className="panel case-detail-panel">
          <div className="finding-card-header">
            <div>
              <h2>{preview.case.title}</h2>
              <p>
                {preview.organization} · {preview.case.caseNumber} · Prepared by {preview.preparedBy} ·{" "}
                Updated {formatDate(preview.case.updatedAt, true)}
              </p>
            </div>
            <div className="finding-badges">
              <SeverityBadge severity={preview.case.severity} />
              <StatusBadge status={preview.case.status} />
            </div>
          </div>
          <div className="case-kpi-grid" style={{ marginTop: "14px" }}>
            <article className="case-kpi-card">
              <span className="case-kpi-label">Evidence items</span>
              <strong>{preview.summary.evidenceCount}</strong>
            </article>
            <article className="case-kpi-card">
              <span className="case-kpi-label">Parsed events</span>
              <strong>{preview.summary.eventsAnalyzed}</strong>
            </article>
            <article className="case-kpi-card">
              <span className="case-kpi-label">Analytical findings</span>
              <strong>{preview.summary.findingsCount}</strong>
            </article>
            <article className="case-kpi-card">
              <span className="case-kpi-label">Custody chain</span>
              <strong>{preview.summary.custodyChainsValid ? "INTACT" : "BROKEN"}</strong>
            </article>
          </div>
        </section>
      )}
    </WorkspaceLayout>
  );
}
