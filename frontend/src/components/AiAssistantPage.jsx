import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { formatDate } from "./CaseFormFields.jsx";
import Icon from "./Icon.jsx";
import WorkspaceLayout from "./WorkspaceLayout.jsx";
import { getCases } from "../services/casesApi.js";
import {
  createAiConversation,
  deleteAiConversation,
  getAiConversation,
  getAiConversations,
  getAiStatus,
  sendAiMessage,
} from "../services/forensicsApi.js";

const SUGGESTED_QUESTIONS = [
  "Summarize this investigation.",
  "What evidence has been registered?",
  "Which evidence has passed SHA-256 verification?",
  "What evidence is missing?",
  "Explain the suspicious events in this case.",
  "Summarize the event timeline.",
  "Explain the detected correlations.",
  "Which findings require investigator review?",
  "Help me draft an investigation report.",
];

function CitationChip({ citation }) {
  if (citation.kind === "case") {
    return (
      <Link className="ioc-chip" to={`/cases/${encodeURIComponent(citation.ref)}`}>
        <small>Case</small>
        <code>{citation.ref}</code>
      </Link>
    );
  }
  if (citation.kind === "evidence") {
    return (
      <Link className="ioc-chip" to={`/evidence/${encodeURIComponent(citation.ref)}`}>
        <small>Evidence</small>
        <code>{citation.ref}</code>
      </Link>
    );
  }
  return (
    <Link className="ioc-chip" to="/analysis/findings">
      <small>{citation.kind || "Ref"}</small>
      <code>{citation.ref}</code>
    </Link>
  );
}

export default function AiAssistantPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialCaseParam = searchParams.get("case") || "";

  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState(initialCaseParam);
  const [aiStatus, setAiStatus] = useState(null);
  const [conversations, setConversations] = useState([]);
  const [activeConv, setActiveConv] = useState(null);
  const [input, setInput] = useState("");

  const [loading, setLoading] = useState(true);
  const [loadingConv, setLoadingConv] = useState(false);
  const [sending, setSending] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [error, setError] = useState("");

  const messagesEndRef = useRef(null);
  const inFlightRef = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getCases({ page: 1, size: 100, signal: controller.signal }),
      getAiStatus({ signal: controller.signal }),
      getAiConversations({ signal: controller.signal }),
    ])
      .then(([casesRes, statusRes, convRes]) => {
        setCases(casesRes.items || []);
        setAiStatus(statusRes);
        const convItems = convRes.items || [];
        setConversations(convItems);
        const fallbackCase = initialCaseParam || casesRes.items?.[0]?.caseNumber || "";
        setSelectedCase((prev) => prev || fallbackCase);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) {
          setError(cause instanceof Error ? cause.message : "Failed to initialize AI Assistant.");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [initialCaseParam]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView?.({ behavior: "smooth" });
  }, [activeConv?.messages?.length]);

  const openConversation = async (conversationCode) => {
    setLoadingConv(true);
    setConfirmClear(false);
    setError("");
    try {
      const detail = await getAiConversation(conversationCode);
      setActiveConv(detail);
      setSelectedCase(detail.caseNumber);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to load conversation.");
    } finally {
      setLoadingConv(false);
    }
  };

  const handleNewConversation = async (caseOverride = "") => {
    const targetCase = caseOverride || selectedCase;
    if (!targetCase) {
      setError("Select an investigation case before starting a conversation.");
      return null;
    }
    setError("");
    setConfirmClear(false);
    try {
      const created = await createAiConversation({ caseId: targetCase });
      setActiveConv(created);
      setConversations((prev) => [created, ...prev.filter((c) => c.conversationCode !== created.conversationCode)]);
      return created;
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not create conversation.");
      return null;
    }
  };

  const handleSend = async (overrideText = null) => {
    const content = (overrideText !== null ? overrideText : input).trim();
    if (!content || sending || inFlightRef.current) return;
    if (!selectedCase && !activeConv) {
      setError("Select a case first to ask the AI Investigation Assistant.");
      return;
    }

    inFlightRef.current = true;
    setSending(true);
    setError("");
    try {
      let conv = activeConv;
      if (!conv || (selectedCase && conv.caseNumber !== selectedCase)) {
        conv = await handleNewConversation(selectedCase);
        if (!conv) return;
      }
      const exchange = await sendAiMessage(conv.conversationCode, content);
      if (overrideText === null) setInput("");
      setActiveConv((prev) => {
        const base = prev && prev.conversationCode === conv.conversationCode ? prev : conv;
        const nextMessages = [...(base.messages || []), exchange.userMessage, exchange.assistantMessage];
        return { ...base, messages: nextMessages, messageCount: nextMessages.length };
      });
      setConversations((prev) =>
        prev.map((c) =>
          c.conversationCode === conv.conversationCode
            ? { ...c, messageCount: (c.messageCount || 0) + 2, updatedAt: exchange.assistantMessage.createdAt }
            : c,
        ),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to send message.");
    } finally {
      setSending(false);
      inFlightRef.current = false;
    }
  };

  const handleClearConversation = async () => {
    if (!activeConv) return;
    setError("");
    try {
      await deleteAiConversation(activeConv.conversationCode);
      setConversations((prev) => prev.filter((c) => c.conversationCode !== activeConv.conversationCode));
      setActiveConv(null);
      setConfirmClear(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to clear conversation.");
    }
  };

  const handleKeyDown = (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      handleSend();
    }
  };

  const modeBadgeLabel =
    aiStatus?.mode === "local_llm"
      ? `Local LLM · ${aiStatus.model}`
      : aiStatus?.mode === "external_llm"
        ? `External AI · ${aiStatus.model}`
        : "Deterministic Synthesis (Offline)";

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : "live"}
      cases={cases}
      selectedCaseId={selectedCase}
      onSelectCase={(c) => c && navigate(`/cases/${encodeURIComponent(c)}`)}
      pageTitle="AI Assistant"
      showSearch={false}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> EVIDENCE-GROUNDED INTELLIGENCE</span>
          <h1>AI Investigation Assistant</h1>
          <p>Ask case-specific questions grounded strictly in authorized evidence, SHA-256 checks, logs, correlations, and findings.</p>
        </div>
        {aiStatus && (
          <span className="page-context" data-testid="ai-mode-badge">
            <Icon name="ai" size={14} /> {modeBadgeLabel}
          </span>
        )}
      </div>

      {aiStatus && (
        <div className="ai-disclaimer" role="note" style={{ marginBottom: "14px" }}>
          {aiStatus.disclaimer}
        </div>
      )}

      {error && (
        <div className="dashboard-error" role="alert" style={{ marginBottom: "14px" }}>
          <Icon name="findings" size={18} />
          <div><strong>Assistant error</strong><p>{error}</p></div>
        </div>
      )}

      <div className="ai-workspace-grid">
        <aside className="panel ai-sidebar-panel">
          <label className="analysis-runner-select" style={{ minWidth: 0 }}>
            <span>Active investigation case</span>
            <select
              aria-label="Select investigation case"
              value={selectedCase}
              onChange={(e) => {
                setSelectedCase(e.target.value);
                if (activeConv && activeConv.caseNumber !== e.target.value) {
                  setActiveConv(null);
                  setConfirmClear(false);
                }
              }}
            >
              {cases.length === 0 ? (
                <option value="">No authorized cases</option>
              ) : (
                cases.map((c) => (
                  <option key={c.caseNumber} value={c.caseNumber}>
                    {c.caseNumber} — {c.title}
                  </option>
                ))
              )}
            </select>
          </label>

          <button
            className="primary-button"
            type="button"
            onClick={() => handleNewConversation(selectedCase)}
            disabled={!selectedCase || sending}
            style={{ width: "100%", justifyContent: "center", marginTop: "10px" }}
          >
            <Icon name="plus" size={14} /> New conversation
          </button>

          <div className="ai-history-header">
            <h3>Conversation History ({conversations.length})</h3>
          </div>
          {loading ? (
            <div className="case-loading">Loading conversations…</div>
          ) : conversations.length === 0 ? (
            <p className="forensic-submeta">No saved conversations yet. Start a session above.</p>
          ) : (
            <ul className="ai-conv-list">
              {conversations.map((conv) => (
                <li key={conv.conversationCode}>
                  <button
                    type="button"
                    className={`ai-conv-item ${activeConv?.conversationCode === conv.conversationCode ? "ai-conv-active" : ""}`}
                    onClick={() => openConversation(conv.conversationCode)}
                  >
                    <strong>{conv.title}</strong>
                    <span>{conv.caseNumber} · {conv.messageCount} msg{conv.messageCount === 1 ? "" : "s"}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </aside>

        <section className="panel ai-chat-panel">
          <div className="ai-chat-header">
            <div>
              <h2>{activeConv ? activeConv.title : "New Investigation Session"}</h2>
              <p className="forensic-submeta">
                {activeConv
                  ? `${activeConv.conversationCode} · Linked to ${activeConv.caseNumber}`
                  : selectedCase
                    ? `Linked to ${selectedCase} · Ask a question below to begin`
                    : "Select a case to begin"}
              </p>
            </div>
            {activeConv && (
              <div>
                {!confirmClear ? (
                  <button
                    className="danger-button"
                    type="button"
                    onClick={() => setConfirmClear(true)}
                    disabled={sending}
                  >
                    Clear conversation
                  </button>
                ) : (
                  <div className="case-delete-confirm" role="alertdialog" aria-label="Confirm clear conversation">
                    <span>Archive chat?</span>
                    <button className="danger-button" type="button" onClick={handleClearConversation}>
                      Confirm
                    </button>
                    <button className="secondary-button" type="button" onClick={() => setConfirmClear(false)}>
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="ai-suggestions" aria-label="Suggested investigation questions">
            {SUGGESTED_QUESTIONS.map((q) => (
              <button
                key={q}
                type="button"
                className="ai-suggestion-chip"
                disabled={sending || !selectedCase}
                onClick={() => handleSend(q)}
              >
                {q}
              </button>
            ))}
          </div>

          <div className="ai-messages-scroll" aria-live="polite">
            {loadingConv ? (
              <div className="ai-thinking-card" role="status">
                <span className="ai-orb ai-orb-sm" aria-hidden="true" />
                <span>Loading conversation history…</span>
              </div>
            ) : !activeConv?.messages?.length ? (
              <div className="ai-empty-hero">
                <div className="ai-orb-wrap" aria-hidden="true">
                  <span className="ai-orb-ring" />
                  <span className="ai-orb"><Icon name="ai" size={22} /></span>
                </div>
                <h3>CyberTrace Investigation Intelligence</h3>
                <p>
                  Select a prompt below or ask any forensic question about <strong>{selectedCase || "your case"}</strong>.
                  Every answer cites authorized workspace records and separates verified facts from recommendations.
                </p>
                <div className="ai-hero-prompts">
                  {SUGGESTED_QUESTIONS.slice(0, 4).map((q) => (
                    <button
                      key={q}
                      type="button"
                      className="ai-hero-card"
                      disabled={sending || !selectedCase}
                      onClick={() => handleSend(q)}
                    >
                      <Icon name="ai" size={14} />
                      <span>{q}</span>
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              activeConv.messages.map((msg) => (
                <article
                  key={msg.id}
                  className={`ai-msg ${msg.role === "user" ? "ai-msg-user" : "ai-msg-assistant"}`}
                >
                  <div className="ai-msg-meta">
                    <span className={`ai-msg-avatar ${msg.role === "user" ? "ai-avatar-user" : "ai-avatar-bot"}`}>
                      {msg.role === "user" ? "IN" : <Icon name="ai" size={13} />}
                    </span>
                    <strong>{msg.role === "user" ? "Investigator" : "CyberTrace Assistant"}</strong>
                    {msg.role === "assistant" && (
                      <span className="analysis-status">
                        {msg.mode === "deterministic" ? "Deterministic" : msg.mode} · {msg.modelName}
                      </span>
                    )}
                    <time dateTime={msg.createdAt}>{formatDate(msg.createdAt, true)}</time>
                  </div>
                  <div className="ai-msg-body">{msg.content}</div>

                  {msg.role === "assistant" && msg.sections && (
                    <div className="ai-sections-grid">
                      {msg.sections.verifiedFacts?.length > 0 && (
                        <div className="ai-section-box ai-section-facts">
                          <strong>Verified Facts</strong>
                          <ul>{msg.sections.verifiedFacts.map((f, i) => <li key={i}>{f}</li>)}</ul>
                        </div>
                      )}
                      {msg.sections.recommendations?.length > 0 && (
                        <div className="ai-section-box ai-section-recs">
                          <strong>Recommendations (Requires Approval)</strong>
                          <ul>{msg.sections.recommendations.map((r, i) => <li key={i}>{r}</li>)}</ul>
                        </div>
                      )}
                    </div>
                  )}

                  {msg.role === "assistant" && msg.citations?.length > 0 && (
                    <div className="ai-citations-row">
                      <span className="forensic-submeta">Citations:</span>
                      <div className="ioc-chip-grid" style={{ marginTop: 0 }}>
                        {msg.citations.map((cit, idx) => (
                          <CitationChip key={`${cit.ref}-${idx}`} citation={cit} />
                        ))}
                      </div>
                    </div>
                  )}

                  {msg.role === "assistant" && msg.sections?.uncertainty && (
                    <p className="forensic-submeta" style={{ marginTop: "6px" }}>
                      {msg.sections.uncertainty}
                    </p>
                  )}
                </article>
              ))
            )}
            {sending && (
              <div className="ai-thinking-card" role="status">
                <span className="ai-orb ai-orb-sm" aria-hidden="true"><Icon name="ai" size={14} /></span>
                <div className="ai-thinking-copy">
                  <strong>Analyzing authorized case records</strong>
                  <span>Retrieving evidence hashes, events, correlations, and findings…</span>
                </div>
                <span className="ai-typing-dots" aria-hidden="true">
                  <i /><i /><i />
                </span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          <form
            className="ai-input-bar"
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
          >
            <textarea
              aria-label="Ask the AI Investigation Assistant"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={
                selectedCase
                  ? `Ask about ${selectedCase}… (Press Enter to send, Shift+Enter for new line)`
                  : "Select a case to ask a question…"
              }
              rows={2}
              disabled={sending || !selectedCase}
            />
            <button
              className="primary-button"
              type="submit"
              disabled={sending || !input.trim() || !selectedCase}
            >
              {sending ? "Sending…" : "Send"}
            </button>
          </form>
        </section>
      </div>
    </WorkspaceLayout>
  );
}
