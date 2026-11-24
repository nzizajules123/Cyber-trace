async function apiRequest(url, options = {}) {
  let response;
  try {
    response = await fetch(url, {
      ...options,
      headers: {
        Accept: "application/json",
        ...(options.body && !(options.body instanceof FormData)
          ? { "Content-Type": "application/json" }
          : {}),
        ...options.headers,
      },
    });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    if (error instanceof TypeError) {
      throw new Error("Cannot reach the CyberTrace API through /api. Ensure FastAPI is running on port 8000.");
    }
    throw error;
  }

  if (response.status === 204) return null;

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      if (response.ok) throw new Error("API returned an unsupported response.");
    }
  }
  if (!response.ok) {
    const msg = payload?.error?.message || payload?.detail || `Request failed (HTTP ${response.status}).`;
    throw new Error(typeof msg === "string" ? msg : `Request failed (HTTP ${response.status}).`);
  }
  return payload;
}

// Evidence & Custody
export function getEvidenceList({ caseId = "", evidenceType = "", query = "", signal } = {}) {
  const params = new URLSearchParams();
  if (caseId) params.set("caseId", caseId);
  if (evidenceType) params.set("evidenceType", evidenceType);
  if (query.trim()) params.set("q", query.trim());
  const qs = params.toString();
  return apiRequest(`/api/v1/evidence${qs ? `?${qs}` : ""}`, { signal });
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

// Log Analysis, IOCs, Findings & Timeline
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

export function getFindings({ caseId = "", status = "", severity = "", signal } = {}) {
  const params = new URLSearchParams();
  if (caseId) params.set("caseId", caseId);
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);
  const qs = params.toString();
  return apiRequest(`/api/v1/analysis/findings${qs ? `?${qs}` : ""}`, { signal });
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

// Reports
export function getCaseReportJson(caseNumber, { signal } = {}) {
  return apiRequest(`/api/v1/reports/cases/${encodeURIComponent(caseNumber)}/json`, { signal });
}

export function getCaseReportPdfUrl(caseNumber) {
  return `/api/v1/reports/cases/${encodeURIComponent(caseNumber)}/pdf`;
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
