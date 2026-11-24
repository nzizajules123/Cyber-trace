import { useEffect, useState } from "react";
import { BrowserRouter, Link, Route, Routes, useNavigate } from "react-router-dom";

import { CaseTimelinePage, ForensicFindingsPage, LogAnalysisPage } from "./components/AnalysisPages.jsx";
import { CaseDetailsPage, CasesPage, EditCasePage, NewCasePage } from "./components/CaseManagement.jsx";
import { AnalyticsPanels, MetricCards, SectionHeading } from "./components/DashboardSections.jsx";
import DigitalFootprintPage from "./components/DigitalFootprintPage.jsx";
import {
  ChainOfCustodyPage,
  EvidenceIntegrityPage,
  EvidenceRepositoryPage,
} from "./components/EvidencePages.jsx";
import Icon from "./components/Icon.jsx";
import { ActivityTimelinePanel, CasesPanel, EvidenceIntegrityPanel } from "./components/InvestigationPanels.jsx";
import ReportsPage from "./components/ReportsPage.jsx";
import WorkspaceLayout from "./components/WorkspaceLayout.jsx";
import { loadDashboardData } from "./services/dashboardApi.js";

function DashboardError({ message, onRetry }) {
  return (
    <div className="dashboard-error" role="alert">
      <Icon name="findings" size={18} />
      <div>
        <strong>Dashboard data is unavailable</strong>
        <p>{message}</p>
      </div>
      <button className="secondary-button" onClick={onRetry}>
        <Icon name="refresh" size={14} /> Retry
      </button>
    </div>
  );
}

function DataModeNotice({ mode, updatedAt }) {
  if (mode === "live") {
    const updatedLabel = updatedAt && !Number.isNaN(new Date(updatedAt).getTime())
      ? new Date(updatedAt).toLocaleString()
      : null;
    return (
      <div className="data-notice live-notice">
        <span className="notice-indicator" />
        <strong>Connected workspace data</strong>
        <span>Values below were returned by the configured CyberTrace API.</span>
        {updatedLabel && <time dateTime={updatedAt}>Updated {updatedLabel}</time>}
      </div>
    );
  }

  return (
    <div className="data-notice demo-notice">
      <Icon name="shield" size={16} />
      <span><strong>Demonstration data</strong> — all cases, counts, events, and charts are illustrative samples, not real investigation records.</span>
    </div>
  );
}

function DashboardPage() {
  const navigate = useNavigate();
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  const [query, setQuery] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");

    loadDashboardData({ signal: controller.signal })
      .then(setDashboard)
      .catch((cause) => {
        if (controller.signal.aborted) return;
        setDashboard(null);
        setError(cause instanceof Error ? cause.message : "An unexpected error occurred.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
  }, [reloadKey]);

  const data = dashboard?.data;
  const cases = data?.cases ?? [];
  const currentCaseId =
    data?.currentCaseId ||
    cases[0]?.caseNumber ||
    cases[0]?.id ||
    "";

  return (
    <WorkspaceLayout
      mode={dashboard?.mode ?? (loading ? "loading" : error ? "unavailable" : "demo")}
      currentUser={data?.currentUser}
      cases={cases}
      selectedCaseId={currentCaseId}
      onSelectCase={(caseNumber) => caseNumber && navigate(`/cases/${encodeURIComponent(caseNumber)}`)}
      query={query}
      onQueryChange={setQuery}
      pageTitle="Dashboard"
    >
      <div className="page-heading" id="overview">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> DIGITAL FORENSICS WORKSPACE</span>
          <h1>Investigation overview</h1>
          <p>Review cases, evidence integrity, and recorded activity in one place.</p>
        </div>
        <span className="page-context"><Icon name="cases" size={15} />{currentCaseId || "No case selected"}</span>
      </div>

      {!loading && dashboard && <DataModeNotice mode={dashboard.mode} updatedAt={data.updatedAt} />}

      {error && <DashboardError message={error} onRetry={() => setReloadKey((key) => key + 1)} />}

      {error && !dashboard ? null : (
        <>
          <section className="dashboard-section metrics-section" aria-label="Investigation metrics">
            <SectionHeading title="Workspace metrics" subtitle="Current totals from the selected data source." />
            <MetricCards metrics={data?.metrics} loading={loading} />
          </section>

          <div className="overview-grid">
            <CasesPanel cases={cases} query={query} loading={loading} />
            <EvidenceIntegrityPanel integrity={data?.evidenceIntegrity} loading={loading} />
          </div>

          <AnalyticsPanels analytics={data?.analytics} cases={cases} loading={loading} />
          <ActivityTimelinePanel events={data?.activityEvents ?? []} query={query} loading={loading} />

          <footer className="dashboard-footer">
            <span><Icon name="shield" size={14} /> CyberTrace <span>·</span> Digital forensics workspace</span>
            <span>{dashboard?.mode === "live" ? "Connected data" : "Illustrative data only"}</span>
          </footer>
        </>
      )}
    </WorkspaceLayout>
  );
}

function ModulePlaceholder({ title }) {
  return (
    <WorkspaceLayout mode="not-implemented" pageTitle={title} showSearch={false}>
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> CYBERTRACE WORKSPACE</span>
          <h1>{title}</h1>
          <p>This destination is available in navigation; its investigation workflow has not been implemented yet.</p>
        </div>
      </div>
      <section className="panel module-placeholder">
        <span className="empty-state-mark"><Icon name="shield" size={18} /></span>
        <h2>Module not implemented</h2>
        <p>No data or actions are simulated on this page. Case Management is the currently available operational module.</p>
        <Link className="secondary-button" to="/cases">Open Cases</Link>
      </section>
    </WorkspaceLayout>
  );
}

function NotFoundPage() {
  return <ModulePlaceholder title="Page not found" />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/cases" element={<CasesPage />} />
        <Route path="/cases/new" element={<NewCasePage />} />
        <Route path="/cases/:caseNumber/edit" element={<EditCasePage />} />
        <Route path="/cases/:caseNumber" element={<CaseDetailsPage />} />
        <Route path="/case-timeline" element={<CaseTimelinePage />} />
        <Route path="/evidence" element={<EvidenceRepositoryPage />} />
        <Route path="/evidence/integrity" element={<EvidenceIntegrityPage />} />
        <Route path="/evidence/chain-of-custody" element={<ChainOfCustodyPage />} />
        <Route path="/analysis/digital-footprint" element={<DigitalFootprintPage />} />
        <Route path="/analysis/log-analysis" element={<LogAnalysisPage />} />
        <Route path="/analysis/event-correlation" element={<ModulePlaceholder title="Event Correlation" />} />
        <Route path="/analysis/findings" element={<ForensicFindingsPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/investigators" element={<ModulePlaceholder title="Investigators" />} />
        <Route path="/audit-logs" element={<ModulePlaceholder title="Audit Logs" />} />
        <Route path="/settings" element={<ModulePlaceholder title="Settings" />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  );
}
