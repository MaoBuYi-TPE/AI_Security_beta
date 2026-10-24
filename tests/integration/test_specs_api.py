"""API 規格的端點（docs/API_CONTRACT.md §15）：上傳走真正的 HTTP、驗證、授權與 commit。

T07 DoD：驗證大小、格式、$ref、servers，包含惡意與跨 origin 的情境；平台不從外部抓取任何東西。
其他 project 的規格與 grant 和不存在的一樣回 404。
"""

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response

from secscan.core.body_limit import MAX_REQUEST_BODY_BYTES
from secscan.specs.domain.documents import MAX_SPEC_BYTES
from secscan.targets.domain import Target
from tests.integration.api_support import MINIMAL_SPEC, Caller, Seeder, World

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "openapi" / "vampi-openapi3.yml"
# tests/fixtures/manifest.json 的 openapi_fixtures：範例 JWT 已遮罩，其他位元組與 T03 的輸入相同。
VAMPI_SHA256 = "039f567e37521f960c8bda26b6b38149303b961f3cb5e7bb3f6c1b99d265ab92"
SPECS = "/api/v1/api-specs"
YAML = {"Content-Type": "application/yaml"}
JSON = {"Content-Type": "application/json"}
CANARY = "canary-spec-0201"


def _of_target(target_id: UUID) -> str:
    return f"/api/v1/targets/{target_id}/api-specs"


def _upload(
    client: TestClient,
    caller: Caller,
    target_id: UUID,
    content: bytes | Iterator[bytes],
    content_type: dict[str, str] = JSON,
) -> Response:
    return client.post(
        _of_target(target_id), content=content, headers={**caller.headers, **content_type}
    )


def _error(response: Response) -> dict[str, Any]:
    body = response.json()
    assert body["success"] is False
    error: dict[str, Any] = body["error"]
    error.pop("request_id")
    return error


def _chunks(content: bytes, size: int = 64 * 1024) -> Iterator[bytes]:
    for start in range(0, len(content), size):
        yield content[start : start + size]


def _spec(**fields: Any) -> bytes:
    document = {
        "openapi": "3.0.3",
        "info": {"title": "t", "version": "1"},
        "paths": {"/items/{id}": {"get": {"operationId": "getItem"}}},
        **fields,
    }
    return json.dumps(document).encode()


@pytest.fixture
def target(seed: Seeder, world: World) -> Target:
    return seed.target(world.operator_a, world.project_a.id, "http://vampi-vuln:5000")


# --- 上傳 -----------------------------------------------------------------------------------


def test_operator_uploads_the_vampi_spec(
    api_client: TestClient, world: World, target: Target
) -> None:
    response = _upload(api_client, world.operator_a, target.id, FIXTURE.read_bytes(), YAML)

    assert response.status_code == 201
    data = response.json()["data"]
    assert data["target_id"] == str(target.id)
    assert data["project_id"] == str(world.project_a.id)
    assert (data["version"], data["openapi_version"], data["source_format"]) == (1, "3.0.1", "yaml")
    assert (data["source_size_bytes"], data["source_sha256"]) == (19631, VAMPI_SHA256)
    assert (data["server_url"], data["base_path"], data["operation_count"]) == (
        "http://vampi-vuln:5000",
        "",
        14,
    )
    assert len(data["document_sha256"]) == 64
    assert data["uploaded_by_key_id"] == str(world.operator_a.principal.key_id)
    assert set(data) == {
        "id",
        "target_id",
        "project_id",
        "version",
        "openapi_version",
        "source_format",
        "source_size_bytes",
        "source_sha256",
        "document_sha256",
        "server_url",
        "base_path",
        "operation_count",
        "uploaded_by_key_id",
        "created_at",
    }


def test_same_content_as_json_gives_the_same_document(
    api_client: TestClient, seed: Seeder, world: World, target: Target
) -> None:
    as_yaml = _upload(api_client, world.operator_a, target.id, FIXTURE.read_bytes(), YAML)
    [row] = seed.query(
        "SELECT document FROM api_specs WHERE id = :id", id=as_yaml.json()["data"]["id"]
    )
    as_json = _upload(
        api_client,
        world.operator_a,
        target.id,
        json.dumps(json.loads(row.document), indent=2).encode(),
        JSON,
    )

    assert as_json.status_code == 201
    first, second = as_yaml.json()["data"], as_json.json()["data"]
    assert (second["version"], second["source_format"]) == (2, "json")
    assert second["document_sha256"] == first["document_sha256"]
    assert second["source_sha256"] != first["source_sha256"]


@pytest.mark.parametrize(
    "content_type",
    [
        "application/yaml; charset=utf-8",
        "APPLICATION/JSON",
        'application/json; charset="UTF-8"',
    ],
)
def test_accepted_content_types(
    api_client: TestClient, world: World, target: Target, content_type: str
) -> None:
    response = _upload(
        api_client, world.operator_a, target.id, MINIMAL_SPEC, {"Content-Type": content_type}
    )

    assert response.status_code == 201


@pytest.mark.parametrize(
    "content_type",
    [
        None,
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
        "application/json; charset=latin-1",
        "text/yaml",
    ],
)
def test_other_content_types_are_415(
    api_client: TestClient, seed: Seeder, world: World, target: Target, content_type: str | None
) -> None:
    headers = {} if content_type is None else {"Content-Type": content_type}

    response = api_client.post(
        _of_target(target.id), content=MINIMAL_SPEC, headers={**world.operator_a.headers, **headers}
    )

    assert response.status_code == 415
    assert _error(response)["code"] == "UNSUPPORTED_MEDIA_TYPE"
    assert seed.query("SELECT 1 FROM api_specs WHERE target_id = :t", t=target.id) == []


def test_spec_at_the_size_limit_is_accepted(
    api_client: TestClient, world: World, target: Target
) -> None:
    content = MINIMAL_SPEC + b" " * (MAX_SPEC_BYTES - len(MINIMAL_SPEC))

    response = _upload(api_client, world.operator_a, target.id, content)

    assert response.status_code == 201
    assert response.json()["data"]["source_size_bytes"] == MAX_SPEC_BYTES


@pytest.mark.parametrize("streamed", [False, True], ids=["content-length", "chunked"])
def test_spec_over_the_size_limit_is_413(
    api_client: TestClient, world: World, target: Target, streamed: bool
) -> None:
    content = MINIMAL_SPEC + b" " * (MAX_SPEC_BYTES + 1 - len(MINIMAL_SPEC))

    response = _upload(
        api_client, world.operator_a, target.id, _chunks(content) if streamed else content
    )

    assert response.status_code == 413
    assert _error(response)["code"] == "SPEC_TOO_LARGE"


def test_request_over_the_global_limit_is_413_before_anything_else(
    api_client: TestClient, world: World, target: Target
) -> None:
    content = b" " * (MAX_REQUEST_BODY_BYTES + 1)

    response = _upload(api_client, world.operator_a, target.id, content)

    assert response.status_code == 413
    assert _error(response)["code"] == "REQUEST_TOO_LARGE"


def test_unknown_key_is_rejected_before_the_body_is_read(
    api_client: TestClient, target: Target
) -> None:
    unknown = {"Authorization": "Bearer " + "_".join(("secscan", "1" * 16, "f" * 64))}
    content = b" " * (MAX_SPEC_BYTES + 1)

    response = api_client.post(_of_target(target.id), content=content, headers={**unknown, **JSON})

    assert response.status_code == 401


@pytest.mark.parametrize(
    ("content", "content_type", "code"),
    [
        (b"a: [1, 2\n", YAML, "INVALID_SPEC"),
        (
            b"openapi: '3.0.3'\ninfo: &i {title: t, version: '1'}\npaths: {}\n",
            YAML,
            "UNSUPPORTED_SCHEMA",
        ),
        (
            _spec(components={"schemas": {"A": {"$ref": f"http://{CANARY}.example/a.yaml"}}}),
            JSON,
            "EXTERNAL_REF_FORBIDDEN",
        ),
        (_spec(openapi="3.1.0"), JSON, "UNSUPPORTED_SCHEMA"),
        (b"", JSON, "INVALID_SPEC"),
    ],
    ids=["broken-yaml", "yaml-anchor", "external-ref", "openapi-3-1", "empty"],
)
def test_rejected_specs_are_422_without_echoing_values(
    api_client: TestClient,
    seed: Seeder,
    world: World,
    target: Target,
    content: bytes,
    content_type: dict[str, str],
    code: str,
) -> None:
    response = _upload(api_client, world.operator_a, target.id, content, content_type)

    assert response.status_code == 422
    assert _error(response)["code"] == code
    assert CANARY not in response.text
    assert seed.query("SELECT 1 FROM api_specs WHERE target_id = :t", t=target.id) == []


def test_cross_origin_servers_are_rebound(
    api_client: TestClient, seed: Seeder, world: World, target: Target
) -> None:
    servers = [{"url": f"http://admin:{CANARY}@{CANARY}.example:8080/api/v1"}]

    response = _upload(api_client, world.operator_a, target.id, _spec(servers=servers))

    assert response.status_code == 201
    data = response.json()["data"]
    assert (data["server_url"], data["base_path"]) == ("http://vampi-vuln:5000/api/v1", "/api/v1")
    assert CANARY not in response.text
    [row] = seed.query("SELECT document FROM api_specs WHERE id = :id", id=data["id"])
    document = json.loads(row.document)
    assert document["servers"] == [{"url": "http://vampi-vuln:5000/api/v1"}]
    assert CANARY.encode() not in row.document


def test_viewer_cannot_upload(
    api_client: TestClient, seed: Seeder, world: World, target: Target
) -> None:
    response = _upload(api_client, world.viewer_a, target.id, MINIMAL_SPEC)

    assert response.status_code == 403
    assert _error(response)["code"] == "ROLE_NOT_ALLOWED"


def test_other_projects_targets_and_specs_look_missing(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    target_b = seed.target(world.admin, world.project_b.id)
    spec_b = seed.spec(world.admin, target_b)
    missing = _error(api_client.get(f"{SPECS}/{uuid4()}", headers=world.operator_a.headers))
    unknown_path = _error(api_client.get("/api/v1/nope", headers=world.operator_a.headers))

    responses = [
        _upload(api_client, world.operator_a, target_b.id, MINIMAL_SPEC),
        api_client.get(_of_target(target_b.id), headers=world.operator_a.headers),
        api_client.get(f"{SPECS}/{spec_b.id}", headers=world.viewer_a.headers),
        api_client.get(f"{SPECS}/{spec_b.id}/operations", headers=world.operator_a.headers),
    ]

    assert missing == unknown_path
    for response in responses:
        assert response.status_code == 404
        assert _error(response) == missing


# --- 查詢 -----------------------------------------------------------------------------------


def test_list_and_get(api_client: TestClient, seed: Seeder, world: World, target: Target) -> None:
    first = seed.spec(world.operator_a, target)
    second = seed.spec(world.operator_a, target)

    listed = api_client.get(
        _of_target(target.id), params={"limit": 1}, headers=world.viewer_a.headers
    )
    single = api_client.get(f"{SPECS}/{first.id}", headers=world.viewer_a.headers)

    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["data"]] == [str(second.id)]
    assert listed.json()["meta"] == {"page": 1, "limit": 1, "total": 2}
    assert single.status_code == 200
    assert single.json()["data"]["version"] == 1


def test_operations_with_and_without_a_grant(
    api_client: TestClient, seed: Seeder, world: World, target: Target
) -> None:
    upload = _upload(api_client, world.operator_a, target.id, FIXTURE.read_bytes(), YAML)
    spec_id = upload.json()["data"]["id"]
    grant = seed.grant(
        world.operator_a,
        target,
        paths=("/users/v1", "/users/v1/{username}"),
        excluded_paths=("/users/v1/_debug",),
        methods=("GET",),
    )

    plain = api_client.get(
        f"{SPECS}/{spec_id}/operations", params={"limit": 2}, headers=world.viewer_a.headers
    )
    previewed = api_client.get(
        f"{SPECS}/{spec_id}/operations",
        params={"limit": 100, "scope_grant_id": str(grant.id)},
        headers=world.viewer_a.headers,
    )

    assert plain.status_code == previewed.status_code == 200
    assert plain.json()["meta"] == {"page": 1, "limit": 2, "total": 14}
    assert plain.json()["data"][0] == {
        "method": "GET",
        "path": "/",
        "operation_id": "api_views.main.basic",
        "eligible": None,
        "reason": None,
    }
    entries = {(item["method"], item["path"]): item for item in previewed.json()["data"]}
    assert entries["GET", "/users/v1"]["eligible"] is True
    assert entries["GET", "/users/v1/_debug"]["reason"] == "PATH_EXCLUDED"
    assert entries["DELETE", "/users/v1/{username}"]["reason"] == "METHOD_NOT_AUTHORIZED"
    assert entries["GET", "/books/v1"] == {
        "method": "GET",
        "path": "/books/v1",
        "operation_id": "api_views.books.get_all_books",
        "eligible": False,
        "reason": "PATH_NOT_AUTHORIZED",
    }


def test_preview_with_another_targets_grant_is_422(
    api_client: TestClient, seed: Seeder, world: World, target: Target
) -> None:
    spec = seed.spec(world.operator_a, target)
    other = seed.target(world.operator_a, world.project_a.id)
    grant = seed.grant(world.operator_a, other)

    response = api_client.get(
        f"{SPECS}/{spec.id}/operations",
        params={"scope_grant_id": str(grant.id)},
        headers=world.operator_a.headers,
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "INVALID_REQUEST"


@pytest.mark.parametrize("params", [{"limit": 101}, {"scope_grant_id": "not-a-uuid"}])
def test_operation_query_parameters_are_validated(
    api_client: TestClient, seed: Seeder, world: World, target: Target, params: dict[str, Any]
) -> None:
    spec = seed.spec(world.operator_a, target)

    response = api_client.get(
        f"{SPECS}/{spec.id}/operations", params=params, headers=world.operator_a.headers
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "INVALID_REQUEST"


def test_only_successful_uploads_are_audited(
    api_client: TestClient, world: World, target: Target
) -> None:
    response = _upload(api_client, world.operator_a, target.id, MINIMAL_SPEC)
    _upload(api_client, world.operator_a, target.id, b"not json")
    _upload(api_client, world.viewer_a, target.id, MINIMAL_SPEC)

    events = api_client.get(
        f"/api/v1/projects/{world.project_a.id}/audit-events",
        params={"limit": 100},
        headers=world.admin.headers,
    ).json()["data"]

    [event] = [event for event in events if event["action"] == "api_spec.create"]
    assert event["object_id"] == response.json()["data"]["id"]
    assert event["actor_key_id"] == str(world.operator_a.principal.key_id)
    assert event["changes"]["format"] == "json"
    assert event["changes"]["document_sha256"] == response.json()["data"]["document_sha256"]


def test_spec_content_never_reaches_the_logs(
    api_client: TestClient, world: World, target: Target, caplog: pytest.LogCaptureFixture
) -> None:
    secret_example = {"/items/{id}": {"get": {"responses": {"200": {"description": CANARY}}}}}
    with caplog.at_level(logging.DEBUG):
        _upload(api_client, world.operator_a, target.id, _spec(paths=secret_example))
        _upload(api_client, world.operator_a, target.id, f"a: {CANARY}\nb: [\n".encode(), YAML)

    assert CANARY not in caplog.text
