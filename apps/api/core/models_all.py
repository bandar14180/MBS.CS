"""Imports every model module so the full set of mapped classes is registered
on Base.metadata. Anything that operates on the ORM without going through the
FastAPI app's router imports (which transitively load everything) -- e.g. the
Celery worker, or Alembic's env.py -- must import this first, or foreign keys
across modules fail to resolve (NoReferencedTableError).
"""

from apps.api.ai_agent import models as ai_agent_models  # noqa: F401
from apps.api.modules.assessment import models as assessment_models  # noqa: F401
from apps.api.modules.assets import models as assets_models  # noqa: F401
from apps.api.modules.api_keys import models as api_keys_models  # noqa: F401
from apps.api.modules.agent import models as agent_models  # noqa: F401
from apps.api.modules.attack import models as attack_models  # noqa: F401
from apps.api.modules.audit import models as audit_models  # noqa: F401
# platform_audit_events: the NON-cascading tenant-deletion audit trail. Its model lives in a
# separate module from audit.models and is imported only by audit/service.py, so omitting it
# here left it off Base.metadata -- and Alembic autogenerate then proposed DROP TABLE on the
# one record that must survive a workspace's hard deletion (AUDIT-001).
from apps.api.modules.audit import platform_models as audit_platform_models  # noqa: F401
from apps.api.modules.auth import models as auth_models  # noqa: F401
from apps.api.modules.authorization_scope import models as authorization_scope_models  # noqa: F401
from apps.api.modules.compliance import models as compliance_models  # noqa: F401
from apps.api.modules.notifications import models as notifications_models  # noqa: F401
from apps.api.modules.private_sites import models as private_sites_models  # noqa: F401
from apps.api.modules.projects import models as projects_models  # noqa: F401
from apps.api.modules.scanner_workers import models as scanner_workers_models  # noqa: F401
from apps.api.modules.remediation import models as remediation_workflow_models  # noqa: F401
from apps.api.modules.remediation import risk_models as risk_treatment_models  # noqa: F401
from apps.api.modules.reports import models as reports_models  # noqa: F401
from apps.api.modules.risk import models as risk_models  # noqa: F401
from apps.api.modules.scans import models as scans_models  # noqa: F401
from apps.api.modules.schedules import models as schedules_models  # noqa: F401
from apps.api.modules.users import models as users_models  # noqa: F401
from apps.api.modules.vulnerabilities import models as vulnerabilities_models  # noqa: F401
from apps.api.modules.vulnerabilities import remediation_models  # noqa: F401
from apps.api.modules.workspaces import models as workspaces_models  # noqa: F401
from apps.api.scanner_engine import models as scanner_engine_models  # noqa: F401
