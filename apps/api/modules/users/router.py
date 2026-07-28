from fastapi import APIRouter, HTTPException, status

from apps.api.core.deps import CurrentUserDep, DbDep
from apps.api.core.security import hash_password, verify_password
from apps.api.modules.users.schemas import PasswordChange, ProfileUpdate, UserRead

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserRead)
async def read_current_user(current_user: CurrentUserDep) -> UserRead:
    return UserRead.model_validate(current_user)


@router.patch("/me", response_model=UserRead)
async def update_profile(payload: ProfileUpdate, db: DbDep, current_user: CurrentUserDep) -> UserRead:
    current_user.full_name = payload.full_name
    await db.commit()
    await db.refresh(current_user)
    return UserRead.model_validate(current_user)


@router.post("/me/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(payload: PasswordChange, db: DbDep, current_user: CurrentUserDep) -> None:
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    current_user.password_hash = hash_password(payload.new_password)
    await db.commit()
