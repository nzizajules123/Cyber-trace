import { demoDashboard } from "../data/demoDashboard.js";
import { apiRequest } from "./apiClient.js";

const DEMO_MODE = import.meta.env.VITE_CYBERTRACE_DEMO_MODE === "true";

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
  const payload = validateDashboardPayload(
    await apiRequest("/api/v1/dashboard/overview", { signal }),
  );
  return { mode: "live", data: payload };
}
