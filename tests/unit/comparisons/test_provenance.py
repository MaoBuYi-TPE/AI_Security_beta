"""複掃所需來源識別必須完整且可重現；未知不等於一致。"""

from dataclasses import replace

import pytest

from secscan.comparisons.domain.provenance import (
    EngineProvenance,
    definition_digest,
    mapping_identity,
)

ENGINE = EngineProvenance(
    engine="zap",
    image_ref="example:1@sha256:" + "a" * 64,
    engine_version="2.16.0",
    parser_version="zap-json/1",
    profile_definition_sha256="b" * 64,
    rule_set_sha256="c" * 64,
    components=(),
)


def test_complete_engine_provenance_has_stable_identity() -> None:
    value = definition_digest(ENGINE)
    assert value is not None
    assert len(value) == 64
    assert definition_digest(ENGINE) == value
    assert definition_digest(replace(ENGINE, parser_version="zap-json/2")) != value


@pytest.mark.parametrize(
    "field",
    [
        "engine",
        "image_ref",
        "engine_version",
        "parser_version",
        "profile_definition_sha256",
        "rule_set_sha256",
    ],
)
def test_missing_engine_provenance_does_not_have_a_comparable_identity(field: str) -> None:
    assert definition_digest(replace(ENGINE, **{field: None})) is None


def test_malformed_digest_is_unknown() -> None:
    assert definition_digest(replace(ENGINE, rule_set_sha256="invalid")) is None
    assert definition_digest(replace(ENGINE, profile_definition_sha256="B" * 64)) is None


def test_mapping_identity_requires_every_engine_to_agree() -> None:
    first = ("rules-2+norm-1+fp-2", "a" * 64)
    assert mapping_identity((first, first)) == first
    assert mapping_identity(()) is None
    assert mapping_identity((first, None)) is None
    assert mapping_identity((first, (first[0], "b" * 64))) is None
    assert mapping_identity((("", "a" * 64),)) is None
    assert mapping_identity(((first[0], "invalid"),)) is None


@pytest.mark.parametrize("image", ["example:1", "example@sha256:" + "a" * 64, "not-an-image"])
def test_image_without_a_pinned_tag_and_digest_is_unknown(image: str) -> None:
    assert definition_digest(replace(ENGINE, image_ref=image)) is None


def test_component_versions_are_part_of_the_definition() -> None:
    first = replace(ENGINE, components=(("pscanrules", "71"),))
    second = replace(first, components=(("pscanrules", "72"),))
    assert definition_digest(first) != definition_digest(second)
    assert definition_digest(replace(first, components=None)) is None


@pytest.mark.parametrize(
    "components",
    [(("pscanrules", ""),), (("", "1"),), (("pscanrules", "71"), ("pscanrules", "72"))],
)
def test_invalid_component_versions_are_unknown(components: tuple[tuple[str, str], ...]) -> None:
    assert definition_digest(replace(ENGINE, components=components)) is None
