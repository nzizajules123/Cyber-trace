from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.case import Case
from app.services.evidence import list_evidence, verify_custody_chain
from app.services.log_analyzer import aggregate_iocs, list_findings, list_forensic_events


def generate_evidence_backed_assistance(
    db: Session,
    *,
    case: Case,
    organization_id: int,
    question: str | None = None,
) -> dict[str, Any]:
    """Controlled, evidence-backed AI Investigation Assistant.

    Principles enforced:
    - Uses ONLY records within the investigator's authorized organization & case.
    - Never fabricates evidence or declares guilt.
    - Never transmits sensitive evidence to external AI providers unless BOTH
      AI_PROVIDER_ENABLED=true and AI_ALLOW_EXTERNAL_DATA=true are explicitly configured.
    - Works 100% locally/offline with deterministic forensic synthesis when external AI is disabled.
    """
    settings = get_settings()
    evidence_items = list_evidence(db, case_ref=case.case_number, organization_id=organization_id)
    events = list_forensic_events(db, case_ref=case.case_number, organization_id=organization_id, limit=500)
    findings = list_findings(db, case_ref=case.case_number, organization_id=organization_id)
    iocs = aggregate_iocs(db, case_ref=case.case_number, organization_id=organization_id)

    citations: list[str] = [case.case_number]
    citations.extend(ev.evidence_code for ev in evidence_items[:10])

    # Build grounded observations strictly from database records
    observations: list[str] = []
    if not evidence_items:
        observations.append(
            f"Case {case.case_number} currently has 0 ingested evidence items. "
            "No forensic conclusions can be drawn until primary artifacts are collected and hashed."
        )
    else:
        intact_chains = sum(1 for ev in evidence_items if verify_custody_chain(ev))
        verified_hashes = sum(
            1
            for ev in evidence_items
            if ev.verifications and ev.verifications[-1].sha256_matches
        )
        observations.append(
            f"Case {case.case_number} contains {len(evidence_items)} evidence item(s) "
            f"({verified_hashes}/{len(evidence_items)} SHA-256 verified, "
            f"{intact_chains}/{len(evidence_items)} custody chains intact)."
        )

    if events:
        types_present = sorted({e.event_type for e in events})
        observations.append(
            f"{len(events)} recorded forensic event(s) have been parsed across categories: {', '.join(types_present)}."
        )
    if findings:
        pending = [f for f in findings if f.status.value == "REQUIRES_REVIEW"]
        confirmed = [f for f in findings if f.status.value == "CONFIRMED"]
        observations.append(
            f"{len(findings)} analytical finding(s) exist ({len(confirmed)} confirmed, {len(pending)} awaiting investigator review)."
        )
        for f in findings[:3]:
            observations.append(
                f"Finding #{f.id} [{f.severity.value} / {f.confidence.value} confidence]: {f.title} — {f.summary}"
            )
    if iocs:
        top_iocs = ", ".join(f"{i.type}:{i.value} (×{i.count})" for i in iocs[:5])
        observations.append(f"Top extracted indicators observed in logs: {top_iocs}.")

    # Identify missing evidence & suggested investigative follow-up questions
    gaps: list[str] = []
    if not evidence_items:
        gaps.append("Ingest primary system, authentication, or network logs into the Evidence Vault.")
    if evidence_items and not events:
        gaps.append("Run automated Log Analysis on ingested evidence to extract structured events and IOCs.")
    if findings and any(f.status.value == "REQUIRES_REVIEW" for f in findings):
        gaps.append("Review and confirm or reject pending analytical findings before finalizing the case report.")
    if not any(ev.evidence_type.value == "NETWORK_CAPTURE" for ev in evidence_items):
        gaps.append("Consider collecting firewall or proxy logs to corroborate external IP activity.")

    suggested_questions = [
        "Were any privileged actions or successful logins authorized via an approved change ticket?",
        "Do the observed external IP addresses appear in other cases or threat intelligence feeds?",
        "Are host clocks synchronized (NTP/UTC) across all collected evidence sources?",
    ]
    if question and question.strip():
        suggested_questions.insert(0, f"Investigator query noted: \"{question.strip()}\" — verify directly against cited evidence items.")

    mode = (
        "external-authorized"
        if (settings.ai_provider_enabled and settings.ai_allow_external_data and settings.ai_provider_url)
        else "local-deterministic"
    )

    return {
        "disclaimer": (
            "AI-Assisted Suggestion — Requires Investigator Review. "
            "All statements below summarize only authorized records in this case and do not establish guilt or legal conclusions."
        ),
        "mode": mode,
        "externalDataTransmitted": False,
        "caseNumber": case.case_number,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "citations": citations,
        "summary": " ".join(observations),
        "observations": observations,
        "missingEvidenceOrGaps": gaps,
        "suggestedQuestions": suggested_questions,
        "uncertaintyNote": (
            "Automated correlations and log patterns highlight anomalies for human review; "
            "independent corroboration from primary evidence is required."
        ),
    }
