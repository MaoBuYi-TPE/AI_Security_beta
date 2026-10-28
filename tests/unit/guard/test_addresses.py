"""DNS 答案的檢查（docs/DECISIONS.md §15.5 第 7 步、SEC-04、SEC-06）：每一個答案都要合格。"""

from ipaddress import IPv4Address, IPv4Network

import pytest

from secscan.guard.domain.addresses import MAX_DNS_ANSWERS, pick_upstream
from secscan.targets.domain import LabNetwork

LAB = LabNetwork(IPv4Network("10.89.7.0/24"))
ALLOWED = frozenset({IPv4Address("10.89.7.20"), IPv4Address("10.89.7.21")})
GUARD = frozenset({IPv4Address("10.89.7.254"), IPv4Address("10.89.8.254")})


def _pick(answers: list[str], allowed: frozenset[IPv4Address] = ALLOWED) -> IPv4Address | None:
    return pick_upstream(answers, allowed=allowed, lab=LAB, guard=GUARD)


def test_single_allowed_answer_is_picked() -> None:
    assert _pick(["10.89.7.20"]) == IPv4Address("10.89.7.20")


def test_several_allowed_answers_pick_the_lowest() -> None:
    assert _pick(["10.89.7.21", "10.89.7.20"]) == IPv4Address("10.89.7.20")


@pytest.mark.parametrize(
    "answers",
    [
        [],
        ["10.89.7.20", "10.89.7.99"],  # 混合：其中一個不在 allowed_ips（DNS rebinding）
        ["10.89.7.99"],
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["010.89.7.20"],
        ["10.89.7.20 "],
        ["::ffff:10.89.7.20"],
        ["fe80::1"],
        ["not-an-ip"],
    ],
)
def test_any_unacceptable_answer_rejects_the_lookup(answers: list[str]) -> None:
    assert _pick(answers) is None


def test_allowed_ips_outside_the_current_lab_are_rejected() -> None:
    """LAB_CIDR 在 grant 核准之後縮小了：guard 以目前的網段為準。"""
    allowed = frozenset({IPv4Address("10.89.9.20")})

    assert _pick(["10.89.9.20"], allowed) is None


@pytest.mark.parametrize("address", ["10.89.7.254", "10.89.7.0", "10.89.7.255"])
def test_reserved_lab_addresses_are_rejected_even_if_listed(address: str) -> None:
    allowed = frozenset({IPv4Address(address)})

    assert _pick([address], allowed) is None


def test_the_guard_itself_is_never_an_upstream() -> None:
    allowed = frozenset({IPv4Address("10.89.7.20")})
    lab = LabNetwork(IPv4Network("10.89.0.0/16"))

    assert (
        pick_upstream(
            ["10.89.7.20"], allowed=allowed, lab=lab, guard=frozenset({IPv4Address("10.89.7.20")})
        )
        is None
    )


def test_too_many_answers_are_rejected() -> None:
    allowed = frozenset(IPv4Address(f"10.89.7.{last}") for last in range(1, 100))
    answers = [f"10.89.7.{last}" for last in range(1, MAX_DNS_ANSWERS + 2)]

    assert _pick(answers[:MAX_DNS_ANSWERS], allowed) is not None
    assert _pick(answers, allowed) is None
