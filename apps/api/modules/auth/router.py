from fastapi import APIRouter, status

from apps.api.core.deps import DbDep
from apps.api.modules.auth import service
from apps.api.modules.auth.schemas import LoginRequest, LogoutRequest, RefreshRequest, RegisterRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: DbDep) -> TokenResponse:
    user = await service.register_user(db, payload.email, payload.password, payload.full_name)
    return await service.issue_token_pair(db, user)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: DbDep) -> TokenResponse:
    user = await service.authenticate_user(db, payload.email, payload.password)
    return await service.issue_token_pair(db, user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, db: DbDep) -> TokenResponse:
    return await service.rotate_refresh_token(db, payload.refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(payload: LogoutRequest, db: DbDep) -> None:
    await service.revoke_refresh_token(db, payload.refresh_token)
