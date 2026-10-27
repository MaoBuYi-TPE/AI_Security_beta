"""Alembic 與測試共用的完整 metadata：在這裡登記所有功能模組的 ORM model。

新增 <feature>/models.py 時要加到 MODELS；tests/unit/test_migrations_layout.py 會抓漏登記。
"""

from secscan.api_keys.models import ApiKeyModel
from secscan.audit.models import AuditEventModel
from secscan.auth_profiles.models import AuthProfileModel, AuthProfileVersionModel
from secscan.core.db import Base
from secscan.grants.models import ScopeGrantModel
from secscan.projects.models import ProjectModel
from secscan.scans.models import (
    ScanEventModel,
    ScanModel,
    ScannerRunModel,
    ScanOperationModel,
)
from secscan.specs.models import ApiSpecModel, ApiSpecOperationModel
from secscan.targets.models import TargetModel

MODELS = (
    ProjectModel,
    ApiKeyModel,
    AuditEventModel,
    TargetModel,
    ScopeGrantModel,
    ApiSpecModel,
    ApiSpecOperationModel,
    AuthProfileModel,
    AuthProfileVersionModel,
    ScanModel,
    ScannerRunModel,
    ScanEventModel,
    ScanOperationModel,
)
target_metadata = Base.metadata
