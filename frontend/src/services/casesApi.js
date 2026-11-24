const CASES_URL = "/api/v1/cases";

function getErrorMessage(payload, statusCode) {
  const apiError = payload?.error;
  if (typeof apiError?.message === "string") return apiError.message;
  const detail = payload?.detail;
  if (statusCode === 404 && detail === "Not Found") {
    return "Cases API route not found (HTTP 404). Restart the CyberTrace backend and confirm /api/v1/cases is registered.";
  }
  if ((statusCode === 502 || statusCode === 503) && typeof detail !== "string") {
    return `The backend is unavailable through the /api proxy (HTTP ${statusCode}). Start FastAPI on port 8000 and check its database configuration.`;
  }
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const messages = detail.map((item) => item?.msg).filter((message) => typeof message === "string");
    if (messages.length) return messages.join(" ");
  }
  return `Case request failed (HTTP ${statusCode}).`;
}

async function request(path = "", options = {}) {
  let response;
  try {
    response = await fetch(`${CASES_URL}${path}`, {
      ...options,
      headers: {
        Accept: "application/json",
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...options.headers,
      },
    });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    if (error instanceof TypeError) {
      throw new Error("Cannot reach the Cases API through the /api proxy. Start FastAPI on port 8000.");
    }
    throw error;
  }

  if (response.status === 204) {
    return null;
  }

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      if (response.ok) throw new Error("The case API returned an unsupported response.");
    }
  }

  if (!response.ok) throw new Error(getErrorMessage(payload, response.status));
  if (payload === null) {
    throw new Error("The case API returned an empty response.");
  }
  return payload;
}

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
  const result = await request("/metrics", { signal });
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

  const result = await request(`?${params.toString()}`, { signal });
  if (!Array.isArray(result.items) || !Number.isInteger(result.total) || !Number.isInteger(result.page) || !Number.isInteger(result.size)) {
    throw new Error("The case API returned a list in an unsupported format.");
  }
  return { ...result, items: result.items.map(validateCase) };
}

export async function getCase(caseNumber, { signal } = {}) {
  return validateCase(await request(`/${encodeURIComponent(caseNumber)}`, { signal }));
}

export async function createCase(values) {
  return validateCase(await request("", { method: "POST", body: JSON.stringify(values) }));
}

export async function updateCase(caseNumber, values) {
  return validateCase(
    await request(`/${encodeURIComponent(caseNumber)}`, {
      method: "PATCH",
      body: JSON.stringify(values),
    }),
  );
}

export async function deleteCase(caseNumber) {
  await request(`/${encodeURIComponent(caseNumber)}`, {
    method: "DELETE",
  });
}
