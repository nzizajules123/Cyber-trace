from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.case import Case
from app.services.cases import list_case_notes
from app.services.correlation import correlate_events
from app.services.evidence import list_evidence, verify_custody_chain
from app.services.log_analyzer import (
    aggregate_iocs,
    build_unified_timeline,
    list_findings,
    list_forensic_events,
)

DETERMINISTIC_DISCLAIMER = (
    "Local Deterministic Synthesis — Not a generative LLM (Requires Investigator Review). "
    "All statements summarize only authorized records in this case."
)
LOCAL_LLM_DISCLAIMER = (
    "Local LLM Suggestion — Requires Investigator Review. "
    "Generated locally from authorized case records; verify all conclusions against primary evidence."
)
EXTERNAL_LLM_DISCLAIMER = (
    "External AI Provider Suggestion (Explicitly Authorized) — Requires Investigator Review. "
    "Verify all interpretations against primary evidence before recording official findings."
)
UNCERTAINTY_STATEMENT = (
    "Automated synthesis and correlations highlight patterns for human review only; "
    "they do not establish legal attribution, intent, or guilt."
)


def resolve_ai_runtime_config() -> dict[str, Any]:
    """Resolve active AI mode strictly without silent external fallback."""
    settings = get_settings()
    provider = (settings.ai_provider or "deterministic").strip().lower()
    enabled = bool(settings.ai_provider_enabled)

    if not enabled or provider == "deterministic":
        return {
            "mode": "deterministic",
            "provider": "deterministic",
            "model": "local-deterministic",
            "external_data_allowed": False,
            "is_generative_llm": False,
            "disclaimer": DETERMINISTIC_DISCLAIMER,
        }

    if provider in ("ollama", "local_llm", "local"):
        if not settings.ai_provider_url:
            return {
                "mode": "deterministic",
                "provider": "deterministic",
                "model": "local-deterministic",
                "external_data_allowed": False,
                "is_generative_llm": False,
                "disclaimer": DETERMINISTIC_DISCLAIMER,
            }
        return {
            "mode": "local_llm",
            "provider": "ollama",
            "model": settings.ai_model or "llama3.1",
            "provider_url": settings.ai_provider_url.rstrip("/"),
            "external_data_allowed": False,
            "is_generative_llm": True,
            "disclaimer": LOCAL_LLM_DISCLAIMER,
        }

    if provider in ("external", "openai_compatible", "cloud"):
        # Hard guard: NEVER transmit externally unless explicitly authorized
        if not settings.ai_allow_external_data or not settings.ai_provider_url or not settings.ai_api_key:
            return {
                "mode": "deterministic",
                "provider": "deterministic",
                "model": "local-deterministic",
                "external_data_allowed": False,
                "is_generative_llm": False,
                "disclaimer": (
                    f"{DETERMINISTIC_DISCLAIMER} "
                    "(External AI provider is configured but disabled because AI_ALLOW_EXTERNAL_DATA=true and credentials are required.)"
                ),
            }
        return {
            "mode": "external_llm",
            "provider": "openai_compatible",
            "model": settings.ai_model or "gpt-4o-mini",
            "provider_url": settings.ai_provider_url.rstrip("/"),
            "api_key": settings.ai_api_key,
            "external_data_allowed": True,
            "is_generative_llm": True,
            "disclaimer": EXTERNAL_LLM_DISCLAIMER,
        }

    return {
        "mode": "deterministic",
        "provider": "deterministic",
        "model": "local-deterministic",
        "external_data_allowed": False,
        "is_generative_llm": False,
        "disclaimer": DETERMINISTIC_DISCLAIMER,
    }


def retrieve_case_context(
    db: Session,
    *,
    case: Case,
    organization_id: int,
) -> dict[str, Any]:
    """Controlled retrieval layer: reads ONLY records belonging to (organization_id, case.id)."""
    evidence_items = list_evidence(db, organization_id=organization_id, case_ref=case.case_number)
    events = list_forensic_events(db, organization_id=organization_id, case_ref=case.case_number, limit=250)
    findings = list_findings(db, organization_id=organization_id, case_ref=case.case_number)
    iocs = aggregate_iocs(db, organization_id=organization_id, case_ref=case.case_number)
    correlations = correlate_events(db, organization_id=organization_id, case_ref=case.case_number)
    timeline = build_unified_timeline(db, organization_id=organization_id, case_ref=case.case_number, limit=40)
    notes = list_case_notes(db, case.id)

    evidence_summaries = []
    citations: list[dict[str, str]] = [
        {"kind": "case", "ref": case.case_number, "label": f"{case.case_number}: {case.title}"}
    ]
    for ev in evidence_items:
        latest_ver = ev.verifications[-1] if ev.verifications else None
        chain_ok = verify_custody_chain(ev)
        ver_status = (
            "VERIFIED"
            if (latest_ver and latest_ver.comparison_performed and latest_ver.sha256_matches)
            else ("MISMATCH" if (latest_ver and latest_ver.comparison_performed) else "PENDING")
        )
        evidence_summaries.append(
            {
                "evidenceCode": ev.evidence_code,
                "filename": ev.original_filename,
                "type": ev.evidence_type.value,
                "status": ev.status.value,
                "sha256": ev.sha256,
                "verificationStatus": ver_status,
                "custodyChainIntact": chain_ok,
                "custodyCount": len(ev.custody_events),
            }
        )
        citations.append(
            {"kind": "evidence", "ref": ev.evidence_code, "label": f"{ev.evidence_code} ({ev.original_filename})"}
        )

    for finding in findings[:10]:
        citations.append(
            {"kind": "finding", "ref": f"FINDING-{finding.id}", "label": f"Finding #{finding.id}: {finding.title}"}
        )

    return {
        "case": {
            "caseNumber": case.case_number,
            "title": case.title,
            "status": case.status.value,
            "severity": case.severity.value,
            "assignedTo": case.assigned_to or "Unassigned",
            "reporterName": case.reporter_name or "Not specified",
            "description": case.description or "No description recorded.",
        },
        "evidence": evidence_summaries,
        "events": events,
        "findings": findings,
        "iocs": iocs,
        "correlations": correlations,
        "timeline": timeline,
        "notes": notes,
        "citations": citations,
    }


def _build_deterministic_answer(context: dict[str, Any], question: str | None) -> dict[str, Any]:
    q = (question or "").strip().lower()
    case_meta = context["case"]
    cnum = case_meta["caseNumber"]
    evidence = context["evidence"]
    events = context["events"]
    findings = context["findings"]
    iocs = context["iocs"]
    correlations = context["correlations"]
    timeline = context["timeline"]
    notes = context["notes"]

    verified_ev = [e for e in evidence if e["verificationStatus"] == "VERIFIED"]
    mismatched_ev = [e for e in evidence if e["verificationStatus"] == "MISMATCH"]
    pending_ev = [e for e in evidence if e["verificationStatus"] == "PENDING"]
    pending_findings = [f for f in findings if f.status.value == "REQUIRES_REVIEW"]
    confirmed_findings = [f for f in findings if f.status.value == "CONFIRMED"]

    verified_facts: list[str] = [
        f"Case {cnum} ('{case_meta['title']}') is currently {case_meta['status']} with {case_meta['severity']} severity (assigned to: {case_meta['assignedTo']}).",
        f"Registered evidence items: {len(evidence)} ({len(verified_ev)} SHA-256 verified, {len(mismatched_ev)} mismatched, {len(pending_ev)} pending).",
        f"Parsed forensic events: {len(events)}; recorded investigator notes: {len(notes)}.",
    ]
    observations: list[str] = []
    interpretations: list[str] = []
    recommendations: list[str] = []

    if findings:
        observations.append(
            f"{len(findings)} analytical finding(s) exist ({len(confirmed_findings)} confirmed, {len(pending_findings)} requiring review)."
        )
    if correlations:
        observations.append(f"{len(correlations)} cross-event correlation(s) were detected across recorded events.")
    if iocs:
        observations.append(
            "Top extracted indicators: " + ", ".join(f"{i.type}:{i.value} (×{i.count})" for i in iocs[:6]) + "."
        )

    if not evidence:
        recommendations.append("Register and hash primary artifacts (system logs, auth logs, network captures) in the Evidence Repository.")
    elif not events:
        recommendations.append("Run automated Log Analysis on ingested evidence to extract normalized events and IOCs.")
    if mismatched_ev:
        recommendations.append(
            "URGENT: Re-verify and isolate evidence items with SHA-256 mismatches: "
            + ", ".join(e["evidenceCode"] for e in mismatched_ev)
            + "."
        )
    if pending_findings:
        recommendations.append("Review pending analytical findings and explicitly confirm or reject each before finalizing the case report.")
    if not any(e["type"] == "NETWORK_CAPTURE" for e in evidence):
        recommendations.append("Consider collecting firewall, DNS, or proxy logs to corroborate host-level activity.")

    # Intent-specific grounded response
    if any(k in q for k in ("sha-256", "sha256", "verif", "integrity", "hash")):
        if not evidence:
            answer = f"No evidence items are registered under {cnum}, so no SHA-256 verification checks exist yet."
        else:
            lines = [
                f"SHA-256 verification status for {cnum} ({len(verified_ev)}/{len(evidence)} verified):"
            ]
            for ev in evidence:
                lines.append(
                    f"- {ev['evidenceCode']} ({ev['filename']}): {ev['verificationStatus']} | "
                    f"Custody chain: {'INTACT' if ev['custodyChainIntact'] else 'BROKEN'} | SHA-256: {ev['sha256'][:16]}…"
                )
            answer = "\n".join(lines)
    elif any(k in q for k in ("missing", "gap", "additional evidence", "collect")):
        gaps = list(recommendations) or [
            "No immediate workflow gaps detected; ensure all collected evidence has been independently corroborated."
        ]
        answer = f"Evidence & workflow gap assessment for {cnum}:\n" + "\n".join(f"- {g}" for g in gaps)
    elif any(k in q for k in ("registered", "evidence list", "what evidence")):
        if not evidence:
            answer = f"No evidence items have been registered in case {cnum} yet."
        else:
            answer = f"Registered evidence in {cnum} ({len(evidence)} item(s)):\n" + "\n".join(
                f"- {e['evidenceCode']}: {e['filename']} ({e['type']}, status: {e['status']}, integrity: {e['verificationStatus']})"
                for e in evidence
            )
    elif any(k in q for k in ("correlat", "linked", "relationship")):
        if not correlations:
            answer = f"No event correlations have been detected for {cnum}. Analyze at least one log file with multiple events to enable correlation."
        else:
            answer = f"Detected event correlations for {cnum} ({len(correlations)}):\n" + "\n".join(
                f"- [{c['confidence']}] {c['correlationType']} ({c['key']}): {c['explanation']}"
                for c in correlations[:8]
            )
            interpretations.append("Correlations indicate shared identifiers or temporal proximity; they do not prove causal intent on their own.")
    elif any(k in q for k in ("finding", "require", "review")):
        if not findings:
            answer = f"No analytical findings have been recorded for {cnum} yet."
        else:
            target_list = pending_findings if "review" in q else findings
            if not target_list:
                answer = f"All {len(findings)} finding(s) in {cnum} have already been reviewed ({len(confirmed_findings)} confirmed)."
            else:
                answer = f"Findings for {cnum} ({len(target_list)} shown):\n" + "\n".join(
                    f"- Finding #{f.id} [{f.severity.value} | {f.status.value}]: {f.title} — {f.summary}"
                    for f in target_list[:10]
                )
    elif any(k in q for k in ("timeline", "chronolog", "sequence")):
        if not timeline:
            answer = f"No timeline events are recorded for {cnum} yet."
        else:
            answer = f"Recent unified timeline for {cnum} (showing {min(len(timeline), 10)} of {len(timeline)} entries):\n" + "\n".join(
                f"- [{t.occurred_at.strftime('%Y-%m-%d %H:%M UTC')}] ({t.record_type}) {t.title}: {t.description}"
                for t in timeline[:10]
            )
    elif any(k in q for k in ("suspicious", "anomal", "event", "attack")):
        if not events and not findings:
            answer = f"No parsed log events or suspicious findings exist for {cnum} yet. Ingest and analyze log files first."
        else:
            parts = [f"Suspicious activity review for {cnum}:"]
            for f in findings[:6]:
                parts.append(f"- [Analytical Finding #{f.id} | {f.severity.value}] {f.title}: {f.summary}")
            if not findings:
                parts.append(f"- {len(events)} log event(s) were parsed with no automated detection rules triggered.")
            answer = "\n".join(parts)
            interpretations.append("Unusual log patterns warrant investigator validation and are not standalone proof of wrongdoing.")
    elif any(k in q for k in ("draft", "report")):
        answer = (
            f"Draft Investigation Report Outline for {cnum} — {case_meta['title']}\n"
            f"1. Case Overview: Status {case_meta['status']}, Severity {case_meta['severity']}, Assigned to {case_meta['assignedTo']}.\n"
            f"2. Evidence & Integrity: {len(evidence)} item(s) registered; {len(verified_ev)} passed SHA-256 verification; {len(mismatched_ev)} mismatches.\n"
            f"3. Analysis Summary: {len(events)} recorded events parsed; {len(iocs)} unique IOCs extracted; {len(correlations)} correlation(s) identified.\n"
            f"4. Findings: {len(confirmed_findings)} confirmed, {len(pending_findings)} pending investigator review.\n"
            f"5. Limitations: Conclusions are bounded strictly by the ingested evidence items and require formal investigator sign-off."
        )
    else:
        # Default comprehensive investigation summary
        parts = [
            f"Investigation Summary for {cnum} — {case_meta['title']} ({case_meta['status']} / {case_meta['severity']}):",
            f"• Evidence: {len(evidence)} registered ({len(verified_ev)} SHA-256 verified, {len(mismatched_ev)} mismatched).",
            f"• Log Analysis: {len(events)} parsed events, {len(iocs)} unique IOCs, {len(correlations)} correlation(s).",
            f"• Findings: {len(findings)} total ({len(confirmed_findings)} confirmed, {len(pending_findings)} awaiting review).",
        ]
        if findings:
            parts.append("• Key Findings: " + "; ".join(f"#{f.id} {f.title} [{f.severity.value}]" for f in findings[:3]) + ".")
        if recommendations:
            parts.append("• Recommended Next Step: " + recommendations[0])
        answer = "\n".join(parts)

    if not interpretations:
        interpretations.append(
            "All observations above reflect recorded workspace artifacts and require human investigator judgment for final conclusions."
        )

    return {
        "content": answer,
        "sections": {
            "verifiedFacts": verified_facts,
            "observations": observations,
            "interpretations": interpretations,
            "recommendations": recommendations,
            "uncertainty": UNCERTAINTY_STATEMENT,
        },
        "citations": context["citations"],
    }


def _build_llm_prompt(context: dict[str, Any], question: str) -> list[dict[str, str]]:
    case_meta = context["case"]
    grounded_snapshot = {
        "case": case_meta,
        "evidence": context["evidence"][:15],
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity.value, "status": f.status.value, "summary": f.summary}
            for f in context["findings"][:15]
        ],
        "correlations": context["correlations"][:10],
        "iocs": [{"type": i.type, "value": i.value, "count": i.count} for i in context["iocs"][:20]],
        "eventCount": len(context["events"]),
        "notesCount": len(context["notes"]),
    }
    system_prompt = (
        "You are CyberTrace AI Investigation Assistant. Answer strictly using the authorized JSON case context below. "
        "NEVER invent evidence, IP addresses, users, events, or findings. If information is missing, say so explicitly. "
        "Clearly distinguish Verified Facts, Observations, Interpretations, and Recommendations, and never declare guilt.\n\n"
        f"AUTHORIZED_CASE_CONTEXT: {grounded_snapshot}"
    )
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": question},
    ]


def _call_local_ollama(runtime: dict[str, Any], messages: list[dict[str, str]]) -> str:
    url = f"{runtime['provider_url']}/api/chat"
    try:
        with httpx.Client(timeout=httpx.Timeout(30.0, connect=5.0)) as client:
            resp = client.post(
                url,
                json={"model": runtime["model"], "messages": messages, "stream": False},
            )
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Local LLM provider error: {err}",
        ) from err

    content = (data.get("message") or {}).get("content") or data.get("response")
    if not isinstance(content, str) or not content.strip():
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Local LLM provider returned an empty or invalid response.",
        )
    return content.strip()


def _call_external_llm(runtime: dict[str, Any], messages: list[dict[str, str]]) -> str:
    url = f"{runtime['provider_url']}/v1/chat/completions"
    try:
        with httpx.Client(timeout=httpx.Timeout(30.0, connect=5.0)) as client:
            resp = client.post(
                url,
                headers={"Authorization": f"Bearer {runtime['api_key']}"},
                json={"model": runtime["model"], "messages": messages, "temperature": 0.2},
            )
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"External AI provider error: {err}",
        ) from err

    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="External AI provider returned an invalid response payload.",
        )
    content = (choices[0].get("message") or {}).get("content")
    if not isinstance(content, str) or not content.strip():
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="External AI provider returned an empty response.",
        )
    return content.strip()


def answer_case_question(
    db: Session,
    *,
    case: Case,
    organization_id: int,
    question: str,
) -> dict[str, Any]:
    runtime = resolve_ai_runtime_config()
    context = retrieve_case_context(db, case=case, organization_id=organization_id)
    det = _build_deterministic_answer(context, question)

    if runtime["mode"] == "local_llm":
        llm_text = _call_local_ollama(runtime, _build_llm_prompt(context, question))
        return {
            "content": llm_text,
            "mode": "local_llm",
            "provider": runtime["provider"],
            "model": runtime["model"],
            "external_data_transmitted": False,
            "disclaimer": runtime["disclaimer"],
            "citations": det["citations"],
            "sections": det["sections"],
        }

    if runtime["mode"] == "external_llm":
        llm_text = _call_external_llm(runtime, _build_llm_prompt(context, question))
        return {
            "content": llm_text,
            "mode": "external_llm",
            "provider": runtime["provider"],
            "model": runtime["model"],
            "external_data_transmitted": True,
            "disclaimer": runtime["disclaimer"],
            "citations": det["citations"],
            "sections": det["sections"],
        }

    return {
        "content": det["content"],
        "mode": "deterministic",
        "provider": "deterministic",
        "model": "local-deterministic",
        "external_data_transmitted": False,
        "disclaimer": runtime["disclaimer"],
        "citations": det["citations"],
        "sections": det["sections"],
    }


def generate_evidence_backed_assistance(
    db: Session,
    *,
    case: Case,
    organization_id: int,
    question: str | None = None,
) -> dict[str, Any]:
    """Backward-compatible helper for POST /api/v1/analysis/ai/assist."""
    result = answer_case_question(
        db,
        case=case,
        organization_id=organization_id,
        question=question or "Summarize this investigation.",
    )
    sections = result["sections"]
    return {
        "disclaimer": result["disclaimer"],
        "mode": result["mode"],
        "provider": result["provider"],
        "model": result["model"],
        "externalDataTransmitted": result["external_data_transmitted"],
        "caseNumber": case.case_number,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "citations": [c["ref"] for c in result["citations"]],
        "summary": result["content"],
        "observations": sections.get("observations", []),
        "missingEvidenceOrGaps": sections.get("recommendations", []),
        "suggestedQuestions": [
            "Which evidence has passed SHA-256 verification?",
            "Explain the suspicious events in this case.",
            "Which findings require investigator review?",
        ],
        "uncertaintyNote": sections.get("uncertainty", UNCERTAINTY_STATEMENT),
    }
