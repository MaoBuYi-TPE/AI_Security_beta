"""T33：run 揭露政策來源；一般 scan API 不提供實驗政策選擇。"""

from uuid import UUID

import pytest
from pydantic import ValidationError

from secscan.scans.schemas import ScanCreate
from tests.conftest import ClientFactory


def test_policy_version_is_output_only(make_client: ClientFactory) -> None:
    schemas = make_client("dev").get("/openapi.json").json()["components"]["schemas"]

    assert "guard_policy_version" in schemas["EngineRunOut"]["properties"]
    assert "guard_policy_version" not in schemas["ScanCreate"]["properties"]
    assert schemas["ScanCreate"]["additionalProperties"] is False


@pytest.mark.parametrize("field", ["guard_policy_version", "policy_version"])
def test_scan_input_cannot_select_an_experimental_policy(field: str) -> None:
    with pytest.raises(ValidationError) as caught:
        ScanCreate.model_validate(
            {
                "target_id": str(UUID(int=1)),
                "scope_grant_id": str(UUID(int=2)),
                "profile": "web_active_lab",
                "engines": ["zap"],
                field: "encoded-params-1",
            }
        )

    assert [(error["loc"], error["type"]) for error in caught.value.errors()] == [
        ((field,), "extra_forbidden")
    ]
