"""凍結清單只記當時允許的規則，不代表該規則已完成。"""

import pytest

from secscan.grants.domain.scope import HttpMethod
from secscan.scanners.domain.nuclei.policy import load_templates
from secscan.scanners.domain.rule_set import frozen_rule_set
from secscan.scans.domain.catalog import Engine, ScanProfile


def test_zap_switching_rules_follow_grant_methods() -> None:
    get_only = frozen_rule_set(Engine.ZAP, ScanProfile.WEB_ACTIVE_LAB, (HttpMethod.GET,))
    with_post = frozen_rule_set(
        Engine.ZAP, ScanProfile.WEB_ACTIVE_LAB, (HttpMethod.GET, HttpMethod.POST)
    )
    assert get_only is not None
    assert with_post is not None
    assert "active:40045" not in get_only.rules
    assert "active:40045" in with_post.rules
    assert get_only.sha256 != with_post.sha256
    assert "passive-addon:pscanrules:76" in get_only.rules


def test_nuclei_rule_set_matches_the_locked_templates() -> None:
    frozen = frozen_rule_set(Engine.NUCLEI, ScanProfile.WEB_ACTIVE_LAB, (HttpMethod.GET,))
    assert frozen is not None
    assert frozen.rules == tuple(sorted(template.id for template in load_templates()))


def test_other_engines_do_not_have_finding_rules() -> None:
    assert frozen_rule_set(Engine.PREFLIGHT, None, ()) is None
    assert frozen_rule_set(Engine.FAKE, None, ()) is None


def test_zap_without_profile_is_rejected() -> None:
    with pytest.raises(ValueError, match="profile"):
        frozen_rule_set(Engine.ZAP, None, ())
