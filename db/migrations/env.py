import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import every module that declares models so they register on Base.metadata
# before Alembic diffs against it. Add new modules' models.py here as they're built.
from apps.api.core.db import Base  # noqa: E402
from apps.api.modules.auth import models as auth_models  # noqa: E402,F401
from apps.api.modules.authorization_scope import models as authorization_scope_models  # noqa: E402,F401
from apps.api.modules.projects import models as projects_models  # noqa: E402,F401
from apps.api.modules.users import models as users_models  # noqa: E402,F401
from apps.api.modules.workspaces import models as workspaces_models  # noqa: E402,F401

target_metadata = Base.metadata

db_url = os.environ.get("DATABASE_URL")
if db_url:
    config.set_main_option("sqlalchemy.url", db_url.replace("+asyncpg", ""))


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
