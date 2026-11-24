import { apiRequest, downloadAuthenticatedFile } from "./apiClient.js";

// Evidence & Custody
export function getEvidenceList({ caseId = "", evidenceType = "", query = "", signal } = {}) {
  const params = new URLSearchParams();
  if (caseId) params.set("caseId", caseId);
  if (evidenceType) params.set("evidenceType", evidenceType);
  if (query.trim()) params.set("q", query.trim());
  const qs = params.toString();
  return apiRequest(`/api/v1/evidence${qs ? `?${qs}` : ""}`, { signal });
}

export function getEvidenceDetail(evidenceCode, { signal } = {}) {
  return apiRequest(`/api/v1/evidence/${encodeURIComponent(evidenceCode)}`, { signal });
}

export function downloadEvidence(evidenceCode, filename) {
  return downloadAuthenticatedFile(
    `/api/v1/evidence/${encodeURIComponent(evidenceCode)}/download`,
    filename || `${evidenceCode}.bin`,
  );
}

export function uploadEvidenceFile({ caseId, evidenceType, acquisitionSource, collectedBy, description, file }) {
  const form = new FormData();
  form.append("caseId", caseId);
  form.append("evidenceType", evidenceType || "LOG_FILE");
  if (acquisitionSource) form.append("acquisitionSource", acquisitionSource);
  if (collectedBy) form.append("collectedBy", collectedBy);
  if (description) form.append("description", description);
  form.append("file", file);
  return apiRequest("/api/v1/evidence/upload", { method: "POST", body: form });
}

export function verifyEvidence(evidenceCode, verifiedBy = "") {
  const qs = verifiedBy ? `?verifiedBy=${encodeURIComponent(verifiedBy)}` : "";
  return apiRequest(`/api/v1/evidence/${encodeURIComponent(evidenceCode)}/verify${qs}`, {
    method: "POST",
  });
}

export function getIntegritySummary({ signal } = {}) {
  return apiRequest("/api/v1/evidence/integrity/summary", { signal });
}

export function getCustodyLedger({ evidenceId = "", signal } = {}) {
  const qs = evidenceId ? `?evidenceId=${encodeURIComponent(evidenceId)}` : "";
  return apiRequest(`/api/v1/evidence/custody/ledger${qs}`, { signal });
}

export function addCustodyEvent(evidenceCode, data) {
  return apiRequest(`/api/v1/evidence/${encodeURIComponent(evidenceCode)}/custody`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

// Log Analysis, IOCs, Correlations, Findings, Timeline & AI Assistant
export function analyzeEvidence(evidenceCode) {
  return apiRequest(`/api/v1/analysis/evidence/${encodeURIComponent(evidenceCode)}/analyze`, {
    method: "POST",
  });
}

export function getForensicEvents({ caseId = "", eventType = "", query = "", signal } = {}) {
  const params = new URLSearchParams();
  if (caseId) params.set("caseId", caseId);
  if (eventType) params.set("eventType", eventType);
  if (query.trim()) params.set("q", query.trim());
  const qs = params.toString();
  return apiRequest(`/api/v1/analysis/events${qs ? `?${qs}` : ""}`, { signal });
}

export function getExtractedIocs({ caseId = "", signal } = {}) {
  const qs = caseId ? `?caseId=${encodeURIComponent(caseId)}` : "";
  return apiRequest(`/api/v1/analysis/iocs${qs}`, { signal });
}

export function getEventCorrelations({ caseId = "", signal } = {}) {
  const qs = caseId ? `?caseId=${encodeURIComponent(caseId)}` : "";
  return apiRequest(`/api/v1/analysis/correlations${qs}`, { signal });
}

export function getFindings({ caseId = "", status = "", severity = "", signal } = {}) {
  const params = new URLSearchParams();
  if (caseId) params.set("caseId", caseId);
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);
  const qs = params.toString();
  return apiRequest(`/api/v1/analysis/findings${qs ? `?${qs}` : ""}`, { signal });
}

export function createFinding(data) {
  return apiRequest("/api/v1/analysis/findings", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function reviewFinding(findingId, { status, reviewerNotes }) {
  return apiRequest(`/api/v1/analysis/findings/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify({ status, reviewerNotes: reviewerNotes || null }),
  });
}

export function getUnifiedTimeline({ caseId = "", limit = 150, signal } = {}) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (caseId) params.set("caseId", caseId);
  return apiRequest(`/api/v1/analysis/timeline?${params.toString()}`, { signal });
}

export function askAiAssistant({ caseId, question = "" }) {
  return apiRequest("/api/v1/analysis/ai/assist", {
    method: "POST",
    body: JSON.stringify({ caseId, question: question || null }),
  });
}

// Digital Footprint / Automated URL Research
export function researchWebsiteUrl({ url, caseId, submittedBy, sealAsEvidence = true, notes = "" }) {
  return apiRequest("/api/v1/footprint/research", {
    method: "POST",
    body: JSON.stringify({
      url,
      caseId,
      submittedBy: submittedBy || null,
      sealAsEvidence,
      notes: notes || null,
    }),
  });
}

export function getUrlInvestigations({ caseId = "", signal } = {}) {
  const qs = caseId ? `?caseId=${encodeURIComponent(caseId)}` : "";
  return apiRequest(`/api/v1/footprint${qs}`, { signal });
}

// Reports
export function getCaseReportJson(caseNumber, { signal } = {}) {
  return apiRequest(`/api/v1/reports/cases/${encodeURIComponent(caseNumber)}/json`, { signal });
}

export function downloadCaseReportPdf(caseNumber) {
  return downloadAuthenticatedFile(
    `/api/v1/reports/cases/${encodeURIComponent(caseNumber)}/pdf`,
    `CyberTrace_Report_${caseNumber}.pdf`,
  );
}

// Organization, Investigators, Audit Logs & Settings
export function getCurrentOrganization({ signal } = {}) {
  return apiRequest("/api/v1/organizations/current", { signal });
}

export function updateCurrentOrganization(data) {
  return apiRequest("/api/v1/organizations/current", {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export function getInvestigators({ signal } = {}) {
  return apiRequest("/api/v1/investigators", { signal });
}

export function addInvestigator(data) {
  return apiRequest("/api/v1/investigators", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function updateInvestigator(membershipId, data) {
  return apiRequest(`/api/v1/investigators/${membershipId}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export function getSystemAuditLogs({ action = "", limit = 100, signal } = {}) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (action) params.set("action", action);
  return apiRequest(`/api/v1/audit-logs?${params.toString()}`, { signal });
}

export function updateMyProfile(data) {
  return apiRequest("/api/v1/auth/me", { method: "PATCH", body: JSON.stringify(data) });
}

export function setupMfa() {
  return apiRequest("/api/v1/auth/mfa/setup", { method: "POST" });
}

export function enableMfa(code) {
  return apiRequest("/api/v1/auth/mfa/enable", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}

export function requestPasswordRecovery(email) {
  return apiRequest("/api/v1/auth/password-recovery/request", {
    method: "POST",
    skipAuthEvent: true,
    body: JSON.stringify({ email }),
  });
}

export function confirmPasswordRecovery({ token, newPassword }) {
  return apiRequest("/api/v1/auth/password-recovery/confirm", {
    method: "POST",
    skipAuthEvent: true,
    body: JSON.stringify({ token, newPassword }),
  });
}
