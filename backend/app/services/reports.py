import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.models.case import Case
from app.services.evidence import list_evidence, serialize_evidence_item, verify_custody_chain
from app.services.log_analyzer import aggregate_iocs, list_findings, list_forensic_events, serialize_finding


def build_case_report_payload(
    db: Session,
    case: Case,
    *,
    organization_id: int | None = None,
    organization_name: str = "CyberTrace Workspace",
    prepared_by: str = "system",
) -> dict[str, Any]:
    evidence_items = list_evidence(db, organization_id=organization_id, case_ref=case.case_number)
    findings = list_findings(db, organization_id=organization_id, case_ref=case.case_number)
    events = list_forensic_events(db, organization_id=organization_id, case_ref=case.case_number, limit=500)
    iocs = aggregate_iocs(db, organization_id=organization_id, case_ref=case.case_number)

    custody_records = []
    all_chains_valid = True
    for item in evidence_items:
        chain_ok = verify_custody_chain(item)
        if not chain_ok:
            all_chains_valid = False
        for ev in item.custody_events:
            custody_records.append(
                {
                    "evidenceCode": item.evidence_code,
                    "action": ev.action.value,
                    "actor": ev.actor,
                    "location": ev.location,
                    "notes": ev.notes,
                    "entryHash": ev.entry_hash,
                    "occurredAt": ev.occurred_at.isoformat(),
                }
            )

    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "platform": "CyberTrace Digital Forensics Platform",
        "organization": organization_name,
        "preparedBy": prepared_by,
        "methodology": (
            "Original evidence files are stored untouched and verified using SHA-256 cryptographic digests. "
            "Recorded facts extracted from source artifacts are kept strictly separate from automated analytical findings."
        ),
        "limitations": (
            "Findings reflect only the evidence items ingested into this case. Automated detections require "
            "investigator validation and do not independently establish legal attribution or guilt."
        ),
        "case": {
            "caseNumber": case.case_number,
            "title": case.title,
            "description": case.description,
            "status": case.status.value,
            "severity": case.severity.value,
            "assignedTo": case.assigned_to,
            "reporterName": case.reporter_name,
            "createdAt": case.created_at.isoformat(),
            "updatedAt": case.updated_at.isoformat(),
        },
        "summary": {
            "evidenceCount": len(evidence_items),
            "eventsAnalyzed": len(events),
            "findingsCount": len(findings),
            "uniqueIocs": len(iocs),
            "custodyChainsValid": all_chains_valid,
        },
        "evidence": [serialize_evidence_item(item).model_dump(by_alias=True, mode="json") for item in evidence_items],
        "findings": [serialize_finding(f).model_dump(by_alias=True, mode="json") for f in findings],
        "iocs": [ioc.model_dump(by_alias=True, mode="json") for ioc in iocs],
        "custodyLedger": custody_records,
        "auditHistory": [
            {
                "action": log.action,
                "actor": log.actor,
                "changes": log.changes_json,
                "createdAt": log.created_at.isoformat(),
            }
            for log in case.audit_logs
        ],
    }


def generate_case_pdf_report(
    db: Session,
    case: Case,
    *,
    organization_id: int | None = None,
    organization_name: str = "CyberTrace Workspace",
    prepared_by: str = "system",
) -> bytes:
    payload = build_case_report_payload(
        db,
        case,
        organization_id=organization_id,
        organization_name=organization_name,
        prepared_by=prepared_by,
    )
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title=f"CyberTrace Forensic Report - {case.case_number}",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CyberTitle",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=colors.HexColor("#0e3a4d"),
        spaceAfter=6,
    )
    h2_style = ParagraphStyle(
        "CyberH2",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=colors.HexColor("#102532"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = styles["BodyText"]
    body_style.fontSize = 9
    body_style.leading = 12
    mono_style = ParagraphStyle("Mono", parent=body_style, fontName="Courier", fontSize=7.5, leading=10)

    story: list[Any] = [
        Paragraph("CYBERTRACE DIGITAL FORENSICS INVESTIGATION REPORT", title_style),
        Paragraph(
            f"<b>Case Number:</b> {case.case_number} &nbsp;|&nbsp; "
            f"<b>Status:</b> {case.status.value} &nbsp;|&nbsp; "
            f"<b>Severity:</b> {case.severity.value}",
            body_style,
        ),
        Paragraph(
            f"<b>Generated (UTC):</b> {payload['generatedAt'][:19].replace('T', ' ')} UTC",
            body_style,
        ),
        Spacer(1, 10),
    ]

    # Case Overview Table
    story.append(Paragraph("1. Case Metadata & Executive Summary", h2_style))
    meta_rows = [
        ["Title", Paragraph(case.title, body_style)],
        ["Assigned Investigator", case.assigned_to or "Unassigned"],
        ["Reporter", case.reporter_name or "Not specified"],
        ["Description", Paragraph(case.description or "No description provided.", body_style)],
        [
            "Investigation Totals",
            f"{payload['summary']['evidenceCount']} evidence items, "
            f"{payload['summary']['eventsAnalyzed']} parsed events, "
            f"{payload['summary']['findingsCount']} analytical findings, "
            f"{payload['summary']['uniqueIocs']} unique IOCs",
        ],
        [
            "Chain of Custody Integrity",
            "VERIFIED — All hash-chained custody records intact"
            if payload["summary"]["custodyChainsValid"]
            else "WARNING — Custody chain tampering detected",
        ],
    ]
    meta_table = Table(meta_rows, colWidths=[1.8 * inch, 5.4 * inch])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef4f7")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1a2738")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(meta_table)

    # Evidence Inventory
    story.append(Paragraph("2. Evidence Inventory & Cryptographic Integrity (SHA-256)", h2_style))
    if not payload["evidence"]:
        story.append(Paragraph("No evidence items have been ingested for this case.", body_style))
    else:
        ev_rows = [["Code", "Filename", "Type", "SHA-256 Digest", "Integrity"]]
        for ev in payload["evidence"]:
            latest = ev.get("latestVerification")
            integrity = (
                "MATCH"
                if latest and latest.get("sha256Matches")
                else ("MISMATCH" if latest else "PENDING")
            )
            ev_rows.append(
                [
                    ev["evidenceCode"],
                    Paragraph(ev["originalFilename"], body_style),
                    ev["evidenceType"],
                    Paragraph(ev["sha256"], mono_style),
                    integrity,
                ]
            )
        ev_table = Table(ev_rows, colWidths=[1.1 * inch, 1.5 * inch, 0.9 * inch, 2.9 * inch, 0.8 * inch])
        ev_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102532")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(ev_table)

    # Analytical Findings
    story.append(Paragraph("3. Analytical Findings (Automated Detection)", h2_style))
    if not payload["findings"]:
        story.append(Paragraph("No analytical findings have been generated for this case.", body_style))
    else:
        f_rows = [["Severity", "Status", "Finding", "Summary"]]
        for f in payload["findings"]:
            f_rows.append(
                [
                    f["severity"],
                    f["status"],
                    Paragraph(f["title"], body_style),
                    Paragraph(f["summary"], body_style),
                ]
            )
        f_table = Table(f_rows, colWidths=[0.85 * inch, 1.15 * inch, 2.1 * inch, 3.1 * inch])
        f_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102532")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(f_table)

    # Extracted IOCs
    story.append(Paragraph("4. Extracted Indicators of Compromise (IOCs)", h2_style))
    if not payload["iocs"]:
        story.append(Paragraph("No IOCs extracted yet.", body_style))
    else:
        ioc_rows = [["Type", "Indicator Value", "Occurrences"]]
        for ioc in payload["iocs"][:30]:
            ioc_rows.append([ioc["type"], Paragraph(ioc["value"], mono_style), str(ioc["count"])])
        ioc_table = Table(ioc_rows, colWidths=[1.2 * inch, 4.8 * inch, 1.2 * inch])
        ioc_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102532")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(ioc_table)

    # Chain of Custody Ledger
    story.append(Paragraph("5. Tamper-Evident Chain of Custody Ledger", h2_style))
    if not payload["custodyLedger"]:
        story.append(Paragraph("No custody events recorded.", body_style))
    else:
        c_rows = [["Timestamp (UTC)", "Evidence", "Action", "Actor", "Ledger Hash (SHA-256)"]]
        for ev in payload["custodyLedger"][:30]:
            c_rows.append(
                [
                    ev["occurredAt"][:19].replace("T", " "),
                    ev["evidenceCode"],
                    ev["action"],
                    ev["actor"],
                    Paragraph(ev["entryHash"][:24] + "…", mono_style),
                ]
            )
        c_table = Table(c_rows, colWidths=[1.4 * inch, 1.2 * inch, 1.0 * inch, 1.2 * inch, 2.4 * inch])
        c_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102532")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(c_table)

    # Methodology, Limitations & Conclusions
    story.append(Paragraph("6. Methodology, Limitations & Investigator Conclusions", h2_style))
    story.append(Paragraph(f"<b>Organization:</b> {payload['organization']} &nbsp;|&nbsp; <b>Prepared by:</b> {payload['preparedBy']}", body_style))
    story.append(Paragraph(f"<b>Methodology:</b> {payload['methodology']}", body_style))
    story.append(Paragraph(f"<b>Limitations:</b> {payload['limitations']}", body_style))
    confirmed_count = sum(1 for f in payload["findings"] if f.get("status") == "CONFIRMED")
    pending_count = sum(1 for f in payload["findings"] if f.get("status") == "REQUIRES_REVIEW")
    story.append(
        Paragraph(
            f"<b>Conclusions Summary:</b> {confirmed_count} finding(s) confirmed by investigator review; "
            f"{pending_count} finding(s) remain pending review. Final conclusions remain the sole responsibility of the assigned investigator.",
            body_style,
        )
    )

    doc.build(story)
    return buffer.getvalue()
