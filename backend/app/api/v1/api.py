from fastapi import APIRouter

from app.api.v1.analysis import router as analysis_router
from app.api.v1.auth import audit_router, auth_router, investigators_router, org_router
from app.api.v1.cases import router as cases_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.footprint import router as footprint_router
from app.api.v1.reports import router as reports_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(org_router)
api_router.include_router(investigators_router)
api_router.include_router(audit_router)
api_router.include_router(cases_router)
api_router.include_router(dashboard_router)
api_router.include_router(evidence_router)
api_router.include_router(analysis_router)
api_router.include_router(footprint_router)
api_router.include_router(reports_router)
