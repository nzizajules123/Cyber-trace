# CyberTrace — AI Investigation Assistant Architecture & Governance

## 1. Operating Modes (Strict Separation)
CyberTrace explicitly distinguishes between deterministic forensic synthesis and generative LLMs. It never pretends deterministic synthesis is a generative LLM and **never silently falls back to an external AI service**.

| Mode | Configuration | Generative LLM? | External Data Transmitted? |
| :--- | :--- | :---: | :---: |
| **Local Deterministic Mode (Default)** | `AI_PROVIDER=deterministic`, `AI_PROVIDER_ENABLED=false` | **No** | **No** |
| **Local LLM Mode (Ollama-compatible)** | `AI_PROVIDER=ollama`, `AI_PROVIDER_ENABLED=true`, `AI_PROVIDER_URL=http://127.0.0.1:11434`, `AI_MODEL=llama3.1` | **Yes (Local)** | **No** |
| **External AI Mode (Opt-In Only)** | `AI_PROVIDER=external`, `AI_PROVIDER_ENABLED=true`, `AI_ALLOW_EXTERNAL_DATA=true`, `AI_PROVIDER_URL=...`, `AI_API_KEY=...`, `AI_MODEL=...` | **Yes (Cloud)** | **Yes (Explicitly Authorized)** |

If `AI_PROVIDER=external` is configured without `AI_ALLOW_EXTERNAL_DATA=true` and valid credentials, CyberTrace refuses external transmission and operates strictly in local deterministic mode.

## 2. Controlled Retrieval Layer
The retrieval layer (`retrieve_case_context` in `backend/app/integrations/ai_assistant.py`) enforces strict scope boundaries:
* Only retrieves records belonging to `(auth.organization.id, case.id)`.
* Retrieves Case metadata, Evidence metadata & SHA-256 verification status, Custody chain status, Parsed forensic events, Cross-event correlations, Analytical findings, and Case notes.
* **No unrestricted database access, SQL execution, shell tools, or cross-organization reads** are exposed to any AI provider.

## 3. Forensic Epistemic Boundaries
Every assistant response separates:
* **Verified Facts** (from DB metadata, hashes, and counts)
* **Observations** (parsed events, IOCs, findings)
* **Interpretations** (patterns requiring human validation)
* **Recommendations** (suggested next steps — require investigator approval before becoming official findings)
* **Citations** (direct clickable links to `CT-...` cases, `EV-...` evidence items, and findings)
* **Uncertainty Statement** (explicit notice that AI output does not establish guilt or legal attribution)

## 4. Conversation Privacy & API Endpoints
Conversations (`ai_conversations`, `ai_messages`) are scoped to `(organization_id, user_id, case_id)`. One investigator cannot read or delete another investigator's private conversations.

* `GET /api/v1/ai/status` — Active AI mode, model, and external transmission policy.
* `POST /api/v1/ai/conversations` — Create a case-linked conversation.
* `GET /api/v1/ai/conversations` — List the authenticated investigator's conversations.
* `GET /api/v1/ai/conversations/{id}` — Read full conversation message history.
* `POST /api/v1/ai/conversations/{id}/messages` — Send a question and receive an evidence-grounded response.
* `DELETE /api/v1/ai/conversations/{id}` — Archive/clear conversation (audited).
* `POST /api/v1/analysis/ai/assist` — Backward-compatible one-shot case brief endpoint.
