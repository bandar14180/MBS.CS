import uuid
from datetime import datetime

from pydantic import BaseModel


class ScanStats(BaseModel):
    total: int = 0
    queued: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class VulnerabilityStats(BaseModel):
    total: int = 0
    # "active" = open | confirmed | reopened (i.e. not fixed/false_positive/accepted_risk)
    active: int = 0
    by_severity: SeverityCounts = SeverityCounts()


class RecentScan(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    target_value: str
    scan_type: str
    status: str
    created_at: datetime


class DashboardSummary(BaseModel):
    projects: int
    targets: int
    scans: ScanStats
    vulnerabilities: VulnerabilityStats
    recent_scans: list[RecentScan]
