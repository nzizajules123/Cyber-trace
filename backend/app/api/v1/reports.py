from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_current_auth
from app.db.session import get_db
from app.services.cases import get_case_by_id
from app.services.reports import build_case_report_payload, generate_case_pdf_report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/cases/{case_id}/json")
def export_case_report_json(
    case_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> dict:
    case = get_case_by_id(db, case_id, organization_id=auth.organization.id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return build_case_report_payload(
        db,
        case,
        organization_id=auth.organization.id,
        organization_name=auth.organization.name,
        prepared_by=auth.actor_label,
    )


@router.get("/cases/{case_id}/pdf")
def export_case_report_pdf(
    case_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> Response:
    case = get_case_by_id(db, case_id, organization_id=auth.organization.id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    pdf_bytes = generate_case_pdf_report(
        db,
        case,
        organization_id=auth.organization.id,
        organization_name=auth.organization.name,
        prepared_by=auth.actor_label,
    )
    filename = f"CyberTrace_Report_{case.case_number}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
