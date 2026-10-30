"""標準格式的 UUID（runner 以檔名與 label 找 run；docs/DECISIONS.md §17.2、§17.4）。"""

from uuid import UUID

import pytest

from secscan.core.identifiers import canonical_uuid

RUN = "6f1c2d3e-4b5a-4c6d-8e7f-001122334455"


def test_the_canonical_form_is_accepted() -> None:
    assert canonical_uuid(RUN) == UUID(RUN)


@pytest.mark.parametrize(
    "text",
    [
        RUN.upper(),
        RUN.replace("-", ""),
        "{" + RUN + "}",
        "urn:uuid:" + RUN,
        " " + RUN,
        "not-a-uuid",
        "",
    ],
)
def test_other_spellings_are_rejected(text: str) -> None:
    assert canonical_uuid(text) is None
