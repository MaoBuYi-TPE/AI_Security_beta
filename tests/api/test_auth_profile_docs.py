"""API 文件中的認證設定（docs/DECISIONS.md §12.2）。

secret 是 writeOnly；任何回應的 schema 都沒有 secret。
"""

import json

from tests.conftest import ClientFactory


def test_secret_is_write_only_in_the_api_docs(make_client: ClientFactory) -> None:
    schemas = make_client("dev").get("/openapi.json").json()["components"]["schemas"]

    for name in ("AuthProfileCreate", "AuthProfilePatch"):
        secret = json.dumps(schemas[name]["properties"]["secret"])
        assert '"writeOnly": true' in secret, name
        assert '"format": "password"' in secret, name


def test_no_response_schema_has_a_secret(make_client: ClientFactory) -> None:
    schemas = make_client("dev").get("/openapi.json").json()["components"]["schemas"]
    responses = {name: schema for name, schema in schemas.items() if name.endswith("Out")}

    assert {"AuthProfileOut", "AuthProfileVersionOut", "PreflightOut"} <= set(responses)
    for name, schema in responses.items():
        assert "secret" not in schema.get("properties", {}), name
