import { demoDashboard } from "../data/demoDashboard.js";

const API_BASE_URL = import.meta.env.VITE_CYBERTRACE_API_URL?.trim() || "";
const DEMO_MODE = import.meta.env.VITE_CYBERTRACE_DEMO_MODE === "true";
const DASHBOARD_PATH = "/api/v1/dashboard/overview";

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateDashboardPayload(payload) {
  const valid =
    isRecord(payload) &&
    isRecord(payload.metrics) &&
    Array.isArray(payload.cases) &&
    isRecord(payload.evidenceIntegrity) &&
    Array.isArray(payload.evidenceIntegrity.verificationChecks) &&
    Array.isArray(payload.activityEvents) &&
    isRecord(payload.analytics);

  if (!valid) {
    throw new Error("The dashboard API returned data in an unsupported format.");
  }

  return payload;
}

export async function loadDashboardData({ signal } = {}) {
  if (DEMO_MODE) {
    return { mode: "demo", data: demoDashboard };
  }

  const baseUrl = API_BASE_URL.replace(/\/+$/, "");
  const url = `${baseUrl}${DASHBOARD_PATH}`;
  let response;
  try {
    response = await fetch(url, {
      headers: { Accept: "application/json" },
      ...(baseUrl ? { credentials: "include" } : {}),
      signal,
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    if (error instanceof TypeError) {
      throw new Error("Cannot reach the Dashboard API through the /api proxy. Start FastAPI on port 8000.");
    }
    throw error;
  }

  if (!response.ok) {
    let message = `Dashboard data could not be loaded (HTTP ${response.status}).`;
    try {
      const errBody = await response.json();
      if (typeof errBody?.error?.message === "string") {
        message = errBody.error.message;
      }
    } catch {
      // ignore non-JSON error body
    }
    throw new Error(message);
  }

  const payload = validateDashboardPayload(await response.json());
  return { mode: "live", data: payload };
}
