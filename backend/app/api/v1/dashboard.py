from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_current_auth
from app.db.session import get_db
from app.schemas.dashboard import DashboardOverviewResponse
from app.services.dashboard import get_dashboard_overview

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview", response_model=DashboardOverviewResponse)
def read_dashboard_overview(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> DashboardOverviewResponse:
    return get_dashboard_overview(
        db,
        organization_id=auth.organization.id,
        current_user={
            "displayName": auth.user.full_name,
            "role": auth.role.value.replace("_", " ").title(),
            "organizationName": auth.organization.name,
        },
    )
