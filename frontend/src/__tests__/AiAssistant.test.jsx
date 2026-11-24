import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "../App.jsx";
import { clearStoredToken, setStoredToken } from "../services/apiClient.js";

function mockAuthenticatedFetch({ sendFails = false } = {}) {
  return vi.spyOn(globalThis, "fetch").mockImplementation((url, options = {}) => {
    const target = String(url);
    const method = (options.method || "GET").toUpperCase();

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
    if (target.includes("/api/v1/cases")) {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            items: [
              {
                id: 1,
                caseNumber: "CT-2026-11223344",
                title: "Credential Stuffing Investigation",
                description: "Auth logs",
                status: "OPEN",
                severity: "HIGH",
                assignedTo: "Lead Maya",
                reporterName: "SOC",
                isDeleted: false,
                createdAt: "2026-11-24T00:00:00Z",
                updatedAt: "2026-11-24T00:00:00Z",
              },
            ],
            total: 1,
            page: 1,
            size: 100,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    }
    if (target.includes("/api/v1/ai/status")) {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            mode: "deterministic",
            provider: "deterministic",
            model: "local-deterministic",
            externalDataAllowed: false,
            isGenerativeLlm: false,
            disclaimer: "Local Deterministic Synthesis — Not a generative LLM.",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    }
    if (target.includes("/api/v1/ai/conversations") && method === "GET") {
      return Promise.resolve(
        new Response(JSON.stringify({ items: [], total: 0 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }
    if (target.endsWith("/api/v1/ai/conversations") && method === "POST") {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            id: 10,
            conversationCode: "AI-2026-TEST0001",
            caseId: 1,
            caseNumber: "CT-2026-11223344",
            caseTitle: "Credential Stuffing Investigation",
            title: "CT-2026-11223344 Investigation Session",
            messageCount: 0,
            messages: [],
            createdAt: "2026-11-24T00:00:00Z",
            updatedAt: "2026-11-24T00:00:00Z",
          }),
          { status: 201, headers: { "Content-Type": "application/json" } },
        ),
      );
    }
    if (target.includes("/messages") && method === "POST") {
      if (sendFails) {
        return Promise.resolve(
          new Response(JSON.stringify({ error: { code: "http_error", message: "Local LLM provider error" } }), {
            status: 502,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }
      return Promise.resolve(
        new Response(
          JSON.stringify({
            conversationCode: "AI-2026-TEST0001",
            userMessage: {
              id: 1,
              conversationId: 10,
              role: "user",
              content: "Which evidence has passed SHA-256 verification?",
              mode: "deterministic",
              provider: "deterministic",
              modelName: "local-deterministic",
              externalDataTransmitted: false,
              citations: [],
              sections: {},
              createdAt: "2026-11-24T00:00:01Z",
            },
            assistantMessage: {
              id: 2,
              conversationId: 10,
              role: "assistant",
              content: "EV-2026-SHAOK001 passed SHA-256 verification.",
              mode: "deterministic",
              provider: "deterministic",
              modelName: "local-deterministic",
              externalDataTransmitted: false,
              citations: [
                { kind: "case", ref: "CT-2026-11223344", label: "CT-2026-11223344" },
                { kind: "evidence", ref: "EV-2026-SHAOK001", label: "EV-2026-SHAOK001" },
              ],
              sections: {
                verifiedFacts: ["Case CT-2026-11223344 has 1 verified evidence item."],
                recommendations: ["Review pending findings."],
                uncertainty: "Automated synthesis requires investigator review.",
              },
              createdAt: "2026-11-24T00:00:02Z",
            },
          }),
          { status: 201, headers: { "Content-Type": "application/json" } },
        ),
      );
    }
    return Promise.resolve(new Response("{}", { status: 404 }));
  });
}

describe("CyberTrace AI Investigation Assistant UI", () => {
  beforeEach(() => {
    clearStoredToken();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    clearStoredToken();
  });

  it("protects /ai-assistant for unauthenticated users", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 401 }));
    window.history.pushState({}, "", "/ai-assistant");
    render(<App />);
    expect(await screen.findByRole("heading", { name: /Sign in to CyberTrace/i })).toBeInTheDocument();
  });

  it("renders sidebar link, chat UI, sends messages, and renders evidence citations", async () => {
    setStoredToken("test-token");
    mockAuthenticatedFetch();
    window.history.pushState({}, "", "/ai-assistant");

    render(<App />);
    expect(await screen.findByRole("heading", { name: /AI Investigation Assistant/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /AI Assistant/i })).toBeInTheDocument();
    expect(await screen.findByTestId("ai-mode-badge")).toHaveTextContent(/Deterministic Synthesis/i);

    const input = screen.getByLabelText(/Ask the AI Investigation Assistant/i);
    fireEvent.change(input, { target: { value: "Which evidence has passed SHA-256 verification?" } });
    fireEvent.click(screen.getByRole("button", { name: /^Send$/i }));

    expect(await screen.findByText(/EV-2026-SHAOK001 passed SHA-256 verification\./i, {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /EV-2026-SHAOK001/i })).toBeInTheDocument();
  });

  it("displays an error alert when message submission fails", async () => {
    setStoredToken("test-token");
    mockAuthenticatedFetch({ sendFails: true });
    window.history.pushState({}, "", "/ai-assistant");

    render(<App />);
    await screen.findByRole("heading", { name: /AI Investigation Assistant/i });

    const input = screen.getByLabelText(/Ask the AI Investigation Assistant/i);
    fireEvent.change(input, { target: { value: "Summarize this investigation." } });
    fireEvent.click(screen.getByRole("button", { name: /^Send$/i }));

    await waitFor(() => {
      expect(screen.getByText(/Local LLM provider error/i)).toBeInTheDocument();
    });
  });
});
