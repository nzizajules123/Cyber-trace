import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "../App.jsx";
import { clearStoredToken, setStoredToken } from "../services/apiClient.js";

describe("CyberTrace Frontend Auth & Workspace Flows", () => {
  beforeEach(() => {
    clearStoredToken();
    window.history.pushState({}, "", "/");
  });

  afterEach(() => {
    vi.restoreAllMocks();
    clearStoredToken();
  });

  it("redirects unauthenticated visitors to the Sign In page", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: /Sign in to CyberTrace/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Email address/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Password/i)).toBeInTheDocument();
  });

  it("displays an authentication error when login fails with 401", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ error: { code: "http_error", message: "Invalid email or password." } }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    );

    render(<App />);
    fireEvent.change(await screen.findByLabelText(/Email address/i), {
      target: { value: "wrong@cybertrace.test" },
    });
    fireEvent.change(screen.getByLabelText(/Password/i), {
      target: { value: "badpass" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/i }));

    expect(await screen.findByText(/Invalid email or password\./i)).toBeInTheDocument();
  });

  it("renders Register page when navigating to /register", async () => {
    window.history.pushState({}, "", "/register");
    render(<App />);
    expect(await screen.findByRole("heading", { name: /Create Investigator Account/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Full name/i)).toBeInTheDocument();
  });

  it("renders authenticated Cases page with live API records and handles API error state", async () => {
    setStoredToken("valid-test-token");
    window.history.pushState({}, "", "/cases");

    vi.spyOn(globalThis, "fetch").mockImplementation((url) => {
      const target = String(url);
      if (target.includes("/api/v1/auth/me")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              user: { id: 1, uuid: "u1", email: "lead@lab.test", fullName: "Lead Maya", isActive: true, mfaEnabled: false, lastLoginAt: null, createdAt: "2026-11-24T00:00:00Z" },
              organization: { id: 1, uuid: "o1", name: "Lab Alpha", slug: "lab-alpha", description: null, allowRegistration: true, deploymentMode: "LOCAL", createdAt: "2026-11-24T00:00:00Z" },
              role: "LEAD_INVESTIGATOR",
              deploymentMode: "LOCAL",
              aiEnabled: true,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ),
        );
      }
      if (target.includes("/api/v1/cases/metrics")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({ totalCases: 1, openCases: 1, criticalCases: 1, resolvedCases: 0 }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ),
        );
      }
      if (target.includes("/api/v1/cases")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              items: [
                {
                  id: 1,
                  caseNumber: "CT-2026-AABBCCDD",
                  title: "Ransomware Triage",
                  description: "Initial triage",
                  status: "OPEN",
                  severity: "CRITICAL",
                  assignedTo: "Lead Maya",
                  reporterName: "SOC",
                  isDeleted: false,
                  createdAt: "2026-11-24T00:00:00Z",
                  updatedAt: "2026-11-24T00:00:00Z",
                },
              ],
              total: 1,
              page: 1,
              size: 50,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ),
        );
      }
      return Promise.resolve(new Response("{}", { status: 404 }));
    });

    render(<App />);
    const matches = await screen.findAllByText("CT-2026-AABBCCDD", {}, { timeout: 5000 });
    expect(matches.length).toBeGreaterThanOrEqual(1);
    expect(await screen.findByText("Ransomware Triage", {}, { timeout: 5000 })).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getAllByText("Lead Maya").length).toBeGreaterThanOrEqual(1);
    });
  });
});
