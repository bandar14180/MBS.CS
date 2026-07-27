"""Imports every model module so the full set of mapped classes is registered
on Base.metadata. Anything that operates on the ORM without going through the
FastAPI app's router imports (which transitively load everything) -- e.g. the
Celery worker, or Alembic's env.py -- must import this first, or foreign keys
across modules fail to resolve (NoReferencedTableError).
"""

from apps.api.ai_agent import models as ai_agent_models  # noqa: F401
from apps.api.modules.assets import models as assets_models  # noqa: F401
from apps.api.modules.auth import models as auth_models  # noqa: F401
from apps.api.modules.authorization_scope import models as authorization_scope_models  # noqa: F401
from apps.api.modules.projects import models as projects_models  # noqa: F401
from apps.api.modules.scans import models as scans_models  # noqa: F401
from apps.api.modules.users import models as users_models  # noqa: F401
from apps.api.modules.vulnerabilities import models as vulnerabilities_models  # noqa: F401
from apps.api.modules.workspaces import models as workspaces_models  # noqa: F401
from apps.api.scanner_engine import models as scanner_engine_models  # noqa: F401
