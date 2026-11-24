const TOKEN_STORAGE_KEY = "cybertrace_access_token";
const API_BASE_URL = (import.meta.env.VITE_CYBERTRACE_API_URL?.trim() || "").replace(/\/+$/, "");

export function getStoredToken() {
  try {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
  } catch {
    return "";
  }
}

export function setStoredToken(token) {
  try {
    if (token) window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
    else window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // ignore storage errors in restricted environments
  }
}

export function clearStoredToken() {
  setStoredToken("");
}

function extractErrorMessage(payload, statusCode) {
  const apiError = payload?.error;
  if (typeof apiError?.message === "string") return apiError.message;
  const detail = payload?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const messages = detail.map((item) => item?.msg).filter((m) => typeof m === "string");
    if (messages.length) return messages.join(" ");
  }
  if (statusCode === 401) return "Authentication required. Please sign in.";
  if (statusCode === 403) return "You do not have permission to perform this action.";
  if (statusCode === 502 || statusCode === 503) {
    return `CyberTrace backend is unavailable (HTTP ${statusCode}). Ensure FastAPI is running on port 8000.`;
  }
  return `Request failed (HTTP ${statusCode}).`;
}

export async function apiRequest(path, options = {}) {
  const { timeoutMs = 25000, skipAuthEvent = false, ...fetchOptions } = options;
  const url = `${API_BASE_URL}${path}`;
  const token = getStoredToken();
  const isFormData = fetchOptions.body instanceof FormData;

  const controller = new AbortController();
  const externalSignal = fetchOptions.signal;
  const onExternalAbort = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else externalSignal.addEventListener("abort", onExternalAbort, { once: true });
  }
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);

  let response;
  try {
    response = await fetch(url, {
      ...fetchOptions,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(!isFormData && fetchOptions.body ? { "Content-Type": "application/json" } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...fetchOptions.headers,
      },
    });
  } catch (error) {
    if (externalSignal?.aborted) throw error;
    if (error?.name === "AbortError") {
      throw new Error("The request timed out. Please try again.");
    }
    if (error instanceof TypeError) {
      throw new Error("Cannot reach the CyberTrace API. Start FastAPI on port 8000.");
    }
    throw error;
  } finally {
    window.clearTimeout(timeoutId);
    if (externalSignal) externalSignal.removeEventListener("abort", onExternalAbort);
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
    if (response.status === 401 && !skipAuthEvent) {
      clearStoredToken();
      window.dispatchEvent(new CustomEvent("cybertrace:unauthorized"));
    }
    throw new Error(extractErrorMessage(payload, response.status));
  }

  return payload;
}

export async function downloadAuthenticatedFile(path, filename) {
  const url = `${API_BASE_URL}${path}`;
  const token = getStoredToken();
  const response = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) {
    throw new Error(`Download failed (HTTP ${response.status}).`);
  }
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(objectUrl);
}
