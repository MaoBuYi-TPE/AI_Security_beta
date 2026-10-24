"""api_specs 的 repository：回傳 frozen domain model；文件與 inventory 和 metadata 一起寫入。"""

import hashlib
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from secscan.core.db import ConstraintViolationError
from secscan.core.pagination import PageRequest
from secscan.projects.domain import NewProject
from secscan.projects.repository import ProjectRepository
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.model import NewApiSpec, NormalizedSpec, SpecOperation
from secscan.specs.domain.openapi import normalize_spec
from secscan.specs.models import ApiSpecModel
from secscan.specs.repository import ApiSpecRepository
from secscan.targets.domain import NewTarget, Target, TargetKind, parse_origin
from secscan.targets.repository import TargetRepository
from tests.integration.sql_support import insert_key

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "openapi" / "vampi-openapi3.yml"
ORIGIN = parse_origin("http://vampi-vuln:5000")


def _target(session: Session) -> Target:
    project = ProjectRepository(session).create(NewProject(name=f"lab-{uuid4().hex[:8]}"))
    return TargetRepository(session).create(
        NewTarget(project_id=project.id, name="VAmPI", kind=TargetKind.API, origin=ORIGIN)
    )


def _vampi() -> NormalizedSpec:
    return normalize_spec(FIXTURE.read_bytes(), SpecFormat.YAML, origin=ORIGIN)


def _create(
    session: Session, target: Target, key_id: UUID, *, version: int = 1
) -> tuple[ApiSpecRepository, UUID]:
    repository = ApiSpecRepository(session)
    spec = repository.create(
        NewApiSpec(target_id=target.id, spec=_vampi(), uploaded_by_key_id=key_id), version=version
    )
    return repository, spec.id


def test_create_stores_metadata_document_and_inventory(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    normalized = _vampi()

    spec = ApiSpecRepository(db_session).create(
        NewApiSpec(target_id=target.id, spec=normalized, uploaded_by_key_id=key_id), version=1
    )

    assert (spec.target_id, spec.project_id, spec.version) == (target.id, target.project_id, 1)
    assert spec.origin == ORIGIN
    assert spec.server_url == "http://vampi-vuln:5000"
    assert spec.source_format is SpecFormat.YAML
    assert spec.source_size == normalized.source_size
    assert spec.source_sha256 == normalized.source_sha256
    assert spec.document_sha256 == normalized.document_sha256
    assert (spec.openapi_version, spec.base_path, spec.operation_count) == ("3.0.1", "", 14)
    assert spec.uploaded_by_key_id == key_id
    assert spec.created_at.tzinfo is not None
    stored = db_session.execute(
        text("SELECT document, document_sha256 FROM api_specs WHERE id = :id"), {"id": spec.id}
    ).one()
    assert stored.document == normalized.document
    assert stored.document_sha256 == hashlib.sha256(stored.document).digest()


def test_operations_are_listed_in_inventory_order(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    repository, spec_id = _create(db_session, target, key_id)

    pages = [repository.list_operations(spec_id, PageRequest(page=n, limit=5)) for n in (1, 2, 3)]

    assert [page.total for page in pages] == [14, 14, 14]
    assert [len(page.items) for page in pages] == [5, 5, 4]
    assert tuple(item for page in pages for item in page.items) == _vampi().operations
    assert pages[0].items[0] == SpecOperation("GET", "/", "api_views.main.basic")


def test_get_reads_metadata_without_the_document(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    repository, spec_id = _create(db_session, target, key_id)

    assert ApiSpecModel.document.property.deferred
    spec = repository.get(spec_id)

    assert spec is not None
    assert spec.id == spec_id
    assert repository.get(uuid4()) is None


def test_versions_counts_and_listing(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    other = _target(db_session)
    repository = ApiSpecRepository(db_session)

    assert repository.next_version(target.id) == 1
    assert repository.count_for_target(target.id) == 0
    _create(db_session, target, key_id, version=1)
    _create(db_session, target, key_id, version=2)
    _create(db_session, other, key_id, version=1)

    assert repository.next_version(target.id) == 3
    assert repository.count_for_target(target.id) == 2
    page = repository.list_by_target(target.id, PageRequest(page=1, limit=25))
    assert [spec.version for spec in page.items] == [2, 1]
    assert page.total == 2


def test_duplicate_version_is_a_constraint_violation(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    _create(db_session, target, key_id, version=1)

    with pytest.raises(ConstraintViolationError) as raised, db_session.begin_nested():
        _create(db_session, target, key_id, version=1)

    assert raised.value.constraint == "uq_api_specs_target_id_version"


def test_spec_without_operations(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    content = b'{"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}}'
    normalized = normalize_spec(content, SpecFormat.JSON, origin=ORIGIN)
    repository = ApiSpecRepository(db_session)

    spec = repository.create(
        NewApiSpec(target_id=target.id, spec=normalized, uploaded_by_key_id=key_id), version=1
    )

    assert spec.operation_count == 0
    assert repository.list_operations(spec.id, PageRequest(page=1, limit=25)).total == 0
