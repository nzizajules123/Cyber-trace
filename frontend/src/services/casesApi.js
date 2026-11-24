import { apiRequest } from "./apiClient.js";

const CASES_URL = "/api/v1/cases";

function validateCase(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.caseNumber !== "string" ||
    typeof value.title !== "string" ||
    typeof value.status !== "string"
  ) {
    throw new Error("The case API returned a record in an unsupported format.");
  }
  return value;
}

export async function getCaseMetrics({ signal } = {}) {
  const result = await apiRequest(`${CASES_URL}/metrics`, { signal });
  const fields = ["totalCases", "openCases", "criticalCases", "resolvedCases"];
  if (!fields.every((field) => Number.isInteger(result?.[field]) && result[field] >= 0)) {
    throw new Error("The case metrics API returned an unsupported format.");
  }
  return result;
}

export async function getCases({ query = "", status = "", severity = "", page = 1, size = 50, signal } = {}) {
  const params = new URLSearchParams({ page: String(page), size: String(size) });
  if (query.trim()) params.set("q", query.trim());
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);

  const result = await apiRequest(`${CASES_URL}?${params.toString()}`, { signal });
  if (
    !Array.isArray(result.items) ||
    !Number.isInteger(result.total) ||
    !Number.isInteger(result.page) ||
    !Number.isInteger(result.size)
  ) {
    throw new Error("The case API returned a list in an unsupported format.");
  }
  return { ...result, items: result.items.map(validateCase) };
}

export async function getCase(caseNumber, { signal } = {}) {
  return validateCase(await apiRequest(`${CASES_URL}/${encodeURIComponent(caseNumber)}`, { signal }));
}

export async function createCase(values) {
  return validateCase(await apiRequest(CASES_URL, { method: "POST", body: JSON.stringify(values) }));
}

export async function updateCase(caseNumber, values) {
  return validateCase(
    await apiRequest(`${CASES_URL}/${encodeURIComponent(caseNumber)}`, {
      method: "PATCH",
      body: JSON.stringify(values),
    }),
  );
}

export async function deleteCase(caseNumber) {
  await apiRequest(`${CASES_URL}/${encodeURIComponent(caseNumber)}`, { method: "DELETE" });
}

export async function getCaseNotes(caseNumber, { signal } = {}) {
  return apiRequest(`${CASES_URL}/${encodeURIComponent(caseNumber)}/notes`, { signal });
}

export async function addCaseNote(caseNumber, content) {
  return apiRequest(`${CASES_URL}/${encodeURIComponent(caseNumber)}/notes`, {
    method: "POST",
    body: JSON.stringify({ content }),
  });
}
