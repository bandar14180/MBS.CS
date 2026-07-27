from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from apps.api.core.config import get_settings
from apps.api.modules.assets.router import router as assets_router
from apps.api.modules.auth.router import router as auth_router
from apps.api.modules.authorization_scope.router import router as authorization_scope_router
from apps.api.modules.projects.router import router as projects_router
from apps.api.modules.reports.router import router as reports_router
from apps.api.modules.scans.router import router as scans_router
from apps.api.modules.users.router import router as users_router
from apps.api.modules.vulnerabilities.router import router as vulnerabilities_router
from apps.api.modules.workspaces.router import roles_router as roles_router
from apps.api.modules.workspaces.router import router as workspaces_router

settings = get_settings()

app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix=settings.api_v1_prefix)
app.include_router(users_router, prefix=settings.api_v1_prefix)
app.include_router(workspaces_router, prefix=settings.api_v1_prefix)
app.include_router(roles_router, prefix=settings.api_v1_prefix)
app.include_router(projects_router, prefix=settings.api_v1_prefix)
app.include_router(authorization_scope_router, prefix=settings.api_v1_prefix)
app.include_router(scans_router, prefix=settings.api_v1_prefix)
app.include_router(assets_router, prefix=settings.api_v1_prefix)
app.include_router(vulnerabilities_router, prefix=settings.api_v1_prefix)
app.include_router(reports_router, prefix=settings.api_v1_prefix)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": settings.app_name, "environment": settings.environment}
