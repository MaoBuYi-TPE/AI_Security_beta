"""guard 的流量明細與認證的健康度（docs/DECISIONS.md §20.3、§20.4）。

- 流量明細來自 guard 的 summary（轉送數、各原因的拒絕數、是否用盡、時間）與 telemetry（有上游
  回應的數量）；telemetry 不完整時只留 summary 的部分，不以殘缺的檔案冒充。
- 認證的健康度：帶認證 header、得到上游回應的請求中，被接受（401、403 以外）與被拒絕的數量；
  同一個 (method, path) 先接受過憑證、最後一次卻被拒絕，是「退化」。退化的 operation 達到門檻就是
  失效（token 在掃描中途過期）。只看「最後被拒絕」：不管憑證的公開端點仍回 200，不能以它判斷。
- 探針：auth profile 的 preflight 端點是已知需要認證的。掃描中帶憑證打它被拒絕，憑證在那時已無效
  （也涵蓋 preflight 之後、掃描的第一個請求之前就過期，沒有任何退化可看的情形）。
- 帶認證的請求一個都沒有被接受（只有被拒絕）也是失效：ZAP 沒打到探針時的備援（T16 的審查）。
"""

import uuid

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.guard.domain.telemetry import RunSummary
from secscan.scans.domain.coverage import Exchange
from secscan.scans.domain.traffic import (
    MIN_REGRESSED_OPERATIONS,
    AuthHealth,
    auth_health,
    guard_traffic,
)

RUN_ID = uuid.UUID(int=1)


def _exchange(
    path: str, method: str = "GET", *, auth: bool = True, status: int | None = 200
) -> Exchange:
    return Exchange(method=method, path=path, authenticated=auth, status=status)


def _summary(forwarded: int, **changes: object) -> RunSummary:
    values: dict[str, object] = {
        "run_id": RUN_ID,
        "scan_id": uuid.UUID(int=2),
        "boot_id": uuid.UUID(int=3),
        "forwarded": forwarded,
    }
    return RunSummary(**{**values, **changes})  # type: ignore[arg-type]


def test_accepted_and_rejected_requests_are_counted() -> None:
    exchanges = [
        _exchange("/me"),
        _exchange("/me", status=401),
        _exchange("/books", status=403),
        _exchange("/books", auth=False, status=401),  # 沒帶認證：不算
        _exchange("/slow", status=None),  # 沒有回應：不算
    ]

    assert auth_health(exchanges) == AuthHealth(
        accepted=1, rejected=2, regressed=1, probe_rejected=0
    )


def test_an_operation_that_stops_accepting_the_credential_regressed() -> None:
    exchanges = [
        _exchange("/me"),
        _exchange("/orders", "POST", status=201),
        _exchange("/me", status=401),
        _exchange("/orders", "POST", status=401),
    ]

    health = auth_health(exchanges)

    assert health.regressed == 2
    assert health.lost


def test_public_endpoints_still_answering_do_not_hide_the_loss() -> None:
    """過期的 token 送到不管憑證的端點仍是 200：只看接受過、最後被拒絕的 operation。"""
    exchanges = [
        _exchange("/me"),
        _exchange("/orders"),
        _exchange("/me", status=401),
        _exchange("/orders", status=401),
        _exchange("/public"),
        _exchange("/public"),
    ]

    assert auth_health(exchanges).lost


def test_an_operation_that_recovers_did_not_regress() -> None:
    """被拒絕之後又接受（例如某個 payload 讓端點回 401）：最後一次是接受，不算退化。"""
    exchanges = [_exchange("/me"), _exchange("/me", status=401), _exchange("/me")]

    assert auth_health(exchanges).regressed == 0


def test_never_accepted_is_not_a_regression() -> None:
    """一開始就被拒絕不是退化；但整個 run 沒有一個帶認證的請求被接受，結果都不是以這個身分取得的
    （T16 的審查：preflight 之後就過期、或權限不足），仍判定為失效。
    """
    exchanges = [_exchange("/admin", status=403), _exchange("/admin", status=403)]

    health = auth_health(exchanges)

    assert health == AuthHealth(accepted=0, rejected=2, regressed=0, probe_rejected=0)
    assert health.lost


def test_one_accepted_request_is_enough_to_not_be_all_rejected() -> None:
    health = auth_health([_exchange("/admin", status=403), _exchange("/public")])

    assert not health.lost


def test_operations_are_told_apart_by_method_and_path() -> None:
    exchanges = [
        _exchange("/me"),
        _exchange("/me", "POST", status=401),
        _exchange("/me/", status=401),
    ]

    assert auth_health(exchanges).regressed == 0


def test_one_regressed_operation_is_below_the_threshold() -> None:
    """一個 operation 的最後一次被拒絕可能是 payload 造成的：門檻以上才算失效。"""
    assert MIN_REGRESSED_OPERATIONS == 2
    health = auth_health([_exchange("/me"), _exchange("/me", status=401)])

    assert health.regressed == 1
    assert not health.lost


def test_anonymous_traffic_has_no_credential_to_lose() -> None:
    health = auth_health([_exchange("/", auth=False), _exchange("/x", auth=False, status=401)])

    assert health == AuthHealth(accepted=0, rejected=0, regressed=0, probe_rejected=0)
    assert not health.lost


PROBE = ("GET", "/me")


def test_a_rejected_probe_means_the_credential_was_not_valid() -> None:
    """token 在 preflight 之後、掃描開始之前就過期：沒有接受過，只有探針看得出來。"""
    exchanges = [
        _exchange("/public"),
        _exchange("/me", status=401),
        _exchange("/orders", status=401),
    ]

    health = auth_health(exchanges, probe=PROBE)

    assert (health.regressed, health.probe_rejected) == (0, 1)
    assert health.lost


def test_an_accepted_probe_is_healthy() -> None:
    health = auth_health([_exchange("/me"), _exchange("/me")], probe=PROBE)

    assert health.probe_rejected == 0
    assert not health.lost


def test_the_probe_matches_method_and_path_exactly() -> None:
    exchanges = [
        _exchange("/me", "POST", status=401),
        _exchange("/me/", status=401),
        _exchange("/me", auth=False, status=401),  # 沒帶認證：不是憑證的問題
        _exchange("/me", status=None),
    ]

    assert auth_health(exchanges, probe=PROBE).probe_rejected == 0


@given(st.lists(st.tuples(st.sampled_from(["/a", "/b", "/c"]), st.sampled_from([200, 401, 403]))))
def test_counts_add_up(items: list[tuple[str, int]]) -> None:
    health = auth_health([_exchange(path, status=status) for path, status in items])

    assert health.accepted + health.rejected == len(items)
    assert 0 <= health.regressed <= 3


def test_traffic_keeps_the_guard_summary_and_the_answers() -> None:
    summary = _summary(
        3,
        denied={"PATH_AMBIGUOUS": 2, "METHOD_NOT_AUTHORIZED": 1},
        exhausted=True,
        first_at=1_700_000_000.25,
        last_at=1_700_000_060.5,
    )
    exchanges = (_exchange("/a"), _exchange("/a", status=401), _exchange("/b", status=None))

    traffic = guard_traffic(summary, exchanges, probe=("GET", "/a"))

    assert traffic is not None
    assert traffic.forwarded == 3
    assert traffic.denied == {"METHOD_NOT_AUTHORIZED": 1, "PATH_AMBIGUOUS": 2}
    assert traffic.exhausted
    assert (traffic.first_at, traffic.last_at) == (1_700_000_000.25, 1_700_000_060.5)
    assert traffic.answered == 2
    assert traffic.auth == AuthHealth(accepted=1, rejected=1, regressed=1, probe_rejected=1)


def test_no_summary_means_no_guard_record() -> None:
    assert guard_traffic(None, ()) is None


@pytest.mark.parametrize(
    "exchanges",
    [None, (), (_exchange("/a"),) * 5],
    ids=["unreadable", "missing-lines", "extra-lines"],
)
def test_incomplete_telemetry_keeps_only_the_summary(
    exchanges: tuple[Exchange, ...] | None,
) -> None:
    """telemetry 讀不到或和 summary 的轉送數對不上：不給回應數與認證的計數（沒有依據）。"""
    traffic = guard_traffic(_summary(3, denied={"RATE_LIMITED": 4}), exchanges)

    assert traffic is not None
    assert traffic.denied == {"RATE_LIMITED": 4}
    assert traffic.answered is None
    assert traffic.auth is None


def test_one_missing_line_is_still_complete() -> None:
    """summary 先寫、行後寫（§16.3）：最多少一行，仍算完整（和 coverage 相同的條件）。"""
    traffic = guard_traffic(_summary(2), (_exchange("/a"),))

    assert traffic is not None
    assert traffic.answered == 1


def test_only_rejections_mean_the_credential_never_worked() -> None:
    """preflight 之後、掃描開始之前就過期，而且 ZAP 沒打到 preflight 的端點（T16 的審查）：
    帶認證的請求一個都沒有被接受。
    """
    health = auth_health([_exchange("/me", status=401), _exchange("/orders", status=403)])

    assert (health.accepted, health.regressed, health.probe_rejected) == (0, 0, 0)
    assert health.lost


def test_no_forwarded_requests_is_a_verified_empty_record() -> None:
    """guard 記下轉送 0 個：沒有 telemetry 的檔案也是有依據的（和 results.py 的 _answers 相同）。"""
    traffic = guard_traffic(_summary(0, denied={"PATH_EXCLUDED": 3}), None)

    assert traffic is not None
    assert traffic.answered == 0
    assert traffic.auth == AuthHealth(accepted=0, rejected=0, regressed=0, probe_rejected=0)
    assert not traffic.auth.lost


def test_the_denied_counts_are_read_only() -> None:
    traffic = guard_traffic(_summary(1, denied={"PATH_EXCLUDED": 3}), (_exchange("/a"),))

    assert traffic is not None
    with pytest.raises(TypeError):
        traffic.denied["PATH_EXCLUDED"] = 0  # type: ignore[index]
