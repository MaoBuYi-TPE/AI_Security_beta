"""T17：凍結的 Nuclei 模板清單與執行設定的驗證測試。

守住已提交的 templates.lock.txt 與 policy.py：清單只含 http、落在允許的類別、和 INCLUDE 對帳、
lock 的 sha256 與常數一致、禁用的型別不出現在執行旗標。產生 lock 的實際流程（下載／解壓／跑
nuclei -tl）在 gated live 測試驗證（tests/live/test_nuclei_templates_live.py）。
"""

import hashlib
import re

from secscan.scanners.domain.nuclei import policy
from secscan.scanners.domain.nuclei.selection import reconcile

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# 凍結的執行旗標：以相等斷言鎖死，任何新增的旗標（含 -code/-headless/-cloud-upload/-dashboard 等）
# 都會讓測試失敗（docs/ARCHITECTURE.md §5「必須關閉」）。
_EXPECTED_FROZEN_FLAGS = ("-ni", "-duc", "-pt", "http", "-jsonl", "-silent")


def test_lock_loads_and_matches_include_count() -> None:
    templates = policy.load_templates()
    assert len(templates) == len(policy.INCLUDE_TEMPLATE_IDS)


def test_include_ids_have_no_duplicates() -> None:
    assert len(policy.INCLUDE_TEMPLATE_IDS) == len(set(policy.INCLUDE_TEMPLATE_IDS))


def test_category_tuples_partition_the_include_list() -> None:
    # 各類別 tuple 合起來剛好等於 INCLUDE，且彼此不重疊（改清單時不會漏算或重複）。
    groups = (
        policy.EXPOSURE_TEMPLATE_IDS,
        policy.MISCELLANEOUS_TEMPLATE_IDS,
        policy.MISCONFIGURATION_TEMPLATE_IDS,
        policy.TECHNOLOGY_TEMPLATE_IDS,
        policy.GENERIC_VULNERABILITY_TEMPLATE_IDS,
    )
    combined = [template_id for group in groups for template_id in group]
    assert combined == list(policy.INCLUDE_TEMPLATE_IDS)
    assert len(combined) == len(set(combined))


def test_lock_ids_match_include_exactly() -> None:
    # 不拋例外即為一致（缺少或多出都會失敗）。
    reconcile(policy.INCLUDE_TEMPLATE_IDS, policy.load_templates())


def test_every_template_is_http_in_an_allowed_category() -> None:
    for template in policy.load_templates():
        parts = template.path.split("/")
        assert parts[0] == "http", template.path
        assert template.path.endswith(".yaml"), template.path
        assert parts[1] in policy.ALLOWED_CATEGORIES, template.path


def test_no_excluded_template_types_present() -> None:
    # DoD：禁用 code/headless/dos/fuzzing（這些不是允許的類別，也不該出現在路徑裡）。
    excluded = {"code", "headless", "dos", "fuzzing"}
    for template in policy.load_templates():
        assert not (excluded & set(template.path.split("/"))), template.path


def test_every_template_sha256_is_lowercase_hex() -> None:
    for template in policy.load_templates():
        assert _SHA256_RE.match(template.sha256), template


def test_lock_sha256_constant_matches_file() -> None:
    digest = hashlib.sha256(policy.lock_text().encode("ascii")).hexdigest()
    assert digest == policy.TEMPLATES_LOCK_SHA256


def test_frozen_flags_are_exactly_the_approved_tuple() -> None:
    # 相等斷言：新增任何旗標都要在這裡明確核准（擋下 -cloud-upload/-dashboard 等）。
    assert policy.FROZEN_FLAGS == _EXPECTED_FROZEN_FLAGS


def test_list_type_filter_is_the_shared_type_filter_and_frozen_prefix() -> None:
    # 列舉與執行用同一份型別過濾（不手抄），且 FROZEN_FLAGS 以它開頭。
    assert policy.LIST_TYPE_FILTER == policy.TYPE_FILTER
    assert policy.FROZEN_FLAGS[: len(policy.TYPE_FILTER)] == policy.TYPE_FILTER


def test_active_probe_ids_are_a_subset_of_include() -> None:
    assert set(policy.ACTIVE_PROBE_TEMPLATE_IDS) <= set(policy.INCLUDE_TEMPLATE_IDS)
    # 所有通用主動探測，加上會 POST 的 graphql/waf 偵測，都必須標記為主動。
    assert set(policy.GENERIC_VULNERABILITY_TEMPLATE_IDS) <= set(policy.ACTIVE_PROBE_TEMPLATE_IDS)
    assert {"graphql-detect", "waf-detect"} <= set(policy.ACTIVE_PROBE_TEMPLATE_IDS)


def test_dropped_multi_protocol_templates_are_not_included() -> None:
    # 內容閘門排除的多協定／會改 Host 的模板不得混回白名單（審查回饋）。
    dropped = {
        "cookies-without-httponly",
        "cookies-without-secure",
        "directory-listing",
        "host-header-injection",
    }
    assert not (dropped & set(policy.INCLUDE_TEMPLATE_IDS))


def test_image_is_pinned_by_digest() -> None:
    assert "@sha256:" in str(policy.NUCLEI_IMAGE)


def test_nuclei_definition_sha256_is_stable_hex() -> None:
    first = policy.nuclei_definition_sha256()
    assert _SHA256_RE.match(first)
    assert first == policy.nuclei_definition_sha256()
