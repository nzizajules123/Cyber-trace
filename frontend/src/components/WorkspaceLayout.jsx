import DashboardHeader from "./DashboardHeader.jsx";
import DashboardSidebar from "./DashboardSidebar.jsx";

export default function WorkspaceLayout({
  mode,
  currentUser,
  cases = [],
  selectedCaseId = "",
  onSelectCase = () => {},
  query = "",
  onQueryChange = () => {},
  pageTitle,
  showSearch = true,
  children,
}) {
  return (
    <div className="app-shell">
      <DashboardSidebar mode={mode} />
      <div className="dashboard-main">
        <DashboardHeader
          currentUser={currentUser}
          cases={cases}
          selectedCaseId={selectedCaseId}
          onSelectCase={onSelectCase}
          query={query}
          onQueryChange={onQueryChange}
          pageTitle={pageTitle}
          showSearch={showSearch}
        />
        <main className="dashboard-content">{children}</main>
      </div>
    </div>
  );
}
