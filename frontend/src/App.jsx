import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";

import AiAssistantPage from "./components/AiAssistantPage.jsx";
import { CaseTimelinePage, ForensicFindingsPage, LogAnalysisPage } from "./components/AnalysisPages.jsx";
import { LoginPage, RecoverPasswordPage, RegisterPage } from "./components/AuthPages.jsx";
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
import {
  AuditLogsPage,
  EventCorrelationPage,
  EvidenceDetailPage,
  InvestigatorsPage,
  SettingsPage,
} from "./components/ManagementPages.jsx";
import ReportsPage from "./components/ReportsPage.jsx";
import WorkspaceLayout from "./components/WorkspaceLayout.jsx";
import { AuthProvider, useAuth } from "./context/AuthContext.jsx";
import { loadDashboardData } from "./services/dashboardApi.js";

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  const location = useLocation();
  if (loading) {
    return (
      <div className="auth-shell">
        <div className="case-loading">Verifying investigator session…</div>
      </div>
    );
  }
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return children;
}

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

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/recover-password" element={<RecoverPasswordPage />} />
          <Route path="/" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
          <Route path="/cases" element={<ProtectedRoute><CasesPage /></ProtectedRoute>} />
          <Route path="/cases/new" element={<ProtectedRoute><NewCasePage /></ProtectedRoute>} />
          <Route path="/cases/:caseNumber/edit" element={<ProtectedRoute><EditCasePage /></ProtectedRoute>} />
          <Route path="/cases/:caseNumber" element={<ProtectedRoute><CaseDetailsPage /></ProtectedRoute>} />
          <Route path="/case-timeline" element={<ProtectedRoute><CaseTimelinePage /></ProtectedRoute>} />
          <Route path="/evidence" element={<ProtectedRoute><EvidenceRepositoryPage /></ProtectedRoute>} />
          <Route path="/evidence/integrity" element={<ProtectedRoute><EvidenceIntegrityPage /></ProtectedRoute>} />
          <Route path="/evidence/chain-of-custody" element={<ProtectedRoute><ChainOfCustodyPage /></ProtectedRoute>} />
          <Route path="/evidence/:evidenceCode" element={<ProtectedRoute><EvidenceDetailPage /></ProtectedRoute>} />
          <Route path="/analysis/digital-footprint" element={<ProtectedRoute><DigitalFootprintPage /></ProtectedRoute>} />
          <Route path="/analysis/log-analysis" element={<ProtectedRoute><LogAnalysisPage /></ProtectedRoute>} />
          <Route path="/analysis/event-correlation" element={<ProtectedRoute><EventCorrelationPage /></ProtectedRoute>} />
          <Route path="/analysis/findings" element={<ProtectedRoute><ForensicFindingsPage /></ProtectedRoute>} />
          <Route path="/ai-assistant" element={<ProtectedRoute><AiAssistantPage /></ProtectedRoute>} />
          <Route path="/reports" element={<ProtectedRoute><ReportsPage /></ProtectedRoute>} />
          <Route path="/investigators" element={<ProtectedRoute><InvestigatorsPage /></ProtectedRoute>} />
          <Route path="/audit-logs" element={<ProtectedRoute><AuditLogsPage /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
