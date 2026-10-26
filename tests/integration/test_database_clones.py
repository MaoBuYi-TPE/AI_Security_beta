"""佇列測試用的資料庫：從 migrated template 複製，每個測試一份，用完刪除。

工作佇列會認領任何排隊中的 run：和其他測試共用資料庫時，會認領到別的測試留下的 run。
"""

import pytest
from sqlalchemy import text

from secscan.migrations import head_revision
from tests.integration.conftest import app_engine
from tests.integration.database import DatabaseProvisioner, ProvisionedDatabase

pytestmark = pytest.mark.integration


def _scalar(database: ProvisionedDatabase, statement: str) -> object:
    engine = app_engine(database)
    try:
        with engine.connect() as connection:
            return connection.execute(text(statement)).scalar()
    finally:
        engine.dispose()


def test_a_clone_is_migrated_and_owned_by_the_template_role(
    queue_database: ProvisionedDatabase, queue_template: ProvisionedDatabase
) -> None:
    assert queue_database.name != queue_template.name
    assert queue_database.user == queue_template.user
    assert _scalar(queue_database, "SELECT version_num FROM alembic_version") == head_revision()
    assert _scalar(queue_database, "SELECT current_user") == queue_template.user


def test_clones_do_not_share_rows(
    queue_database: ProvisionedDatabase,
    provisioner: DatabaseProvisioner,
    queue_template: ProvisionedDatabase,
) -> None:
    engine = app_engine(queue_database)
    try:
        with engine.begin() as connection:
            connection.execute(text("INSERT INTO projects (name) VALUES ('only-in-this-clone')"))
    finally:
        engine.dispose()
    other = provisioner.clone(queue_template)
    try:
        assert _scalar(other, "SELECT count(*) FROM projects") == 0
    finally:
        provisioner.drop(other)


def test_dropping_a_clone_keeps_the_template_role(
    provisioner: DatabaseProvisioner, queue_template: ProvisionedDatabase
) -> None:
    clone = provisioner.clone(queue_template)
    provisioner.drop(clone)

    assert _scalar(queue_template, "SELECT current_user") == queue_template.user
