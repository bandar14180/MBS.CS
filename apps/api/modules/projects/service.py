import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.projects.models import Project, Target


async def create_project(
    db: AsyncSession, workspace_id: uuid.UUID, creator_id: uuid.UUID, name: str, description: str | None
) -> Project:
    from apps.api.modules.billing import service as billing

    await billing.enforce_project_quota(db, workspace_id)
    project = Project(workspace_id=workspace_id, name=name, description=description, created_by=creator_id)
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


async def list_projects(db: AsyncSession, workspace_id: uuid.UUID) -> list[Project]:
    result = await db.scalars(
        select(Project).where(Project.workspace_id == workspace_id).order_by(Project.created_at)
    )
    return list(result)


async def get_project(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID) -> Project:
    project = await db.scalar(
        select(Project).where(Project.id == project_id, Project.workspace_id == workspace_id)
    )
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


async def update_project(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    name: str | None,
    description: str | None,
    project_status: str | None,
) -> Project:
    project = await get_project(db, workspace_id, project_id)
    if name is not None:
        project.name = name
    if description is not None:
        project.description = description
    if project_status is not None:
        project.status = project_status
    await db.commit()
    await db.refresh(project)
    return project


async def delete_project(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID) -> None:
    project = await get_project(db, workspace_id, project_id)
    await db.delete(project)
    await db.commit()


async def create_target(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    added_by: uuid.UUID,
    target_type: str,
    value: str,
    criticality: str = "medium",
) -> Target:
    await get_project(db, workspace_id, project_id)  # 404s if project isn't in this workspace

    from apps.api.modules.billing import service as billing

    await billing.enforce_target_quota(db, workspace_id)
    target = Target(
        project_id=project_id, type=target_type, value=value, added_by=added_by, criticality=criticality
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


async def update_target_criticality(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, target_id: uuid.UUID, criticality: str
) -> Target:
    target = await get_target(db, workspace_id, project_id, target_id)
    target.criticality = criticality
    await db.commit()
    await db.refresh(target)
    return target


async def list_targets(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID) -> list[Target]:
    await get_project(db, workspace_id, project_id)
    result = await db.scalars(
        select(Target).where(Target.project_id == project_id).order_by(Target.created_at)
    )
    return list(result)


async def get_target(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, target_id: uuid.UUID
) -> Target:
    await get_project(db, workspace_id, project_id)  # 404s if project isn't in this workspace
    target = await db.scalar(select(Target).where(Target.id == target_id, Target.project_id == project_id))
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    return target
