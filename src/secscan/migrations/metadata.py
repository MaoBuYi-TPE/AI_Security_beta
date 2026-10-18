"""Alembic 與測試共用的完整 metadata：在這裡登記所有功能模組的 ORM model。

新增 <feature>/models.py 時要加到 MODELS；tests/unit/test_migrations_layout.py 會抓漏登記。
"""

from secscan.api_keys.models import ApiKeyModel
from secscan.audit.models import AuditEventModel
from secscan.core.db import Base
from secscan.projects.models import ProjectModel

MODELS = (ProjectModel, ApiKeyModel, AuditEventModel)
target_metadata = Base.metadata
