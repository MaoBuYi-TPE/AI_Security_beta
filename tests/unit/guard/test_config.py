"""guard 的設定與 mitmproxy 的 options（docs/DECISIONS.md §15.1、§15.2）。

環境變數嚴格解析（canonical 的 IP 與網段、guard 的位址固定是兩個網段的最後一個主機位址）；
options 設定之後逐一讀回核對：任何一項不安全就不啟動。
"""

from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any

import pytest

from secscan.guard.config import (
    GUARD_PORT,
    GuardConfig,
    GuardConfigError,
    addon_options,
    config_from_env,
    core_options,
    expected_options,
    option_problems,
)

ENV = {
    "LAB_CIDR": "10.89.7.0/24",
    "GUARD_SCAN_CIDR": "10.89.8.0/24",
    "GUARD_SCAN_IP": "10.89.8.254",
    "GUARD_LAB_IP": "10.89.7.254",
}


def _config(**overrides: str) -> GuardConfig:
    return config_from_env({**ENV, **overrides})


def test_reads_the_environment() -> None:
    config = _config()

    assert config.lab.cidr == IPv4Network("10.89.7.0/24")
    assert config.scan_network == IPv4Network("10.89.8.0/24")
    assert config.listen == f"10.89.8.254:{GUARD_PORT}"
    assert config.guard_ips == frozenset({IPv4Address("10.89.8.254"), IPv4Address("10.89.7.254")})
    assert config.policies_dir == Path("/guard/policies")
    assert config.status_dir == Path("/guard/status")
    assert config.telemetry_dir == Path("/guard/telemetry")
    assert config.confdir == Path("/tmp/mitmproxy")  # noqa: S108


def test_directories_can_be_overridden() -> None:
    config = _config(
        GUARD_POLICIES_DIR="/p", GUARD_STATUS_DIR="/s", GUARD_TELEMETRY_DIR="/t", GUARD_CONFDIR="/c"
    )

    assert (config.policies_dir, config.status_dir, config.telemetry_dir, config.confdir) == (
        Path("/p"),
        Path("/s"),
        Path("/t"),
        Path("/c"),
    )


@pytest.mark.parametrize("missing", sorted(ENV))
def test_required_variables(missing: str) -> None:
    env = {key: value for key, value in ENV.items() if key != missing}

    with pytest.raises(GuardConfigError, match=missing):
        config_from_env(env)


@pytest.mark.parametrize(
    "overrides",
    [
        {"LAB_CIDR": "10.0.0.0/8"},  # 太寬
        {"LAB_CIDR": "8.8.8.0/24"},
        {"LAB_CIDR": "10.89.7.5/24"},  # host bits
        {"LAB_CIDR": "10.89.7.0/24 "},
        {"GUARD_SCAN_CIDR": "10.89.7.0/24"},  # 和 lab 重疊
        {"GUARD_SCAN_CIDR": "10.89.0.0/16"},  # 包含 lab
        {"GUARD_SCAN_CIDR": "8.8.8.0/24"},
        {"GUARD_LAB_IP": "10.89.7.253"},  # 不是保留給 guard 的位址
        {"GUARD_LAB_IP": "010.89.7.254"},
        {"GUARD_SCAN_IP": "10.89.8.20"},  # 在動態配發的範圍內
        {"GUARD_SCAN_IP": "10.89.7.254"},
        {"GUARD_SCAN_IP": "0.0.0.0"},  # noqa: S104 - 測試資料：不能聽所有介面
        {"GUARD_POLICIES_DIR": "relative/path"},
        {"GUARD_STATUS_DIR": "/guard/policies", "GUARD_POLICIES_DIR": "/guard/policies"},
        {"GUARD_TELEMETRY_DIR": "/guard/status"},
        {"GUARD_TELEMETRY_DIR": "telemetry"},
    ],
)
def test_rejects_unsafe_settings(overrides: dict[str, str]) -> None:
    with pytest.raises(GuardConfigError):
        _config(**overrides)


def test_core_options_listen_only_on_the_scan_side() -> None:
    options = core_options(_config())

    assert options["mode"] == [f"regular@10.89.8.254:{GUARD_PORT}"]
    assert options["confdir"] == "/tmp/mitmproxy"  # noqa: S108
    for name in ("upstream_cert", "http2", "http3", "websocket", "rawtcp", "ssl_insecure"):
        assert options[name] is False
    for name in ("ignore_hosts", "allow_hosts", "tcp_hosts", "udp_hosts"):
        assert options[name] == []


def test_addon_options_are_the_documented_safe_values() -> None:
    options = addon_options()

    assert options["connection_strategy"] == "lazy"
    assert options["body_size_limit"] == "16m"
    assert options["stream_large_bodies"] is None
    assert options["validate_inbound_headers"] is True
    assert options["block_global"] is True
    assert options["block_private"] is False
    for name in ("map_remote", "map_local", "modify_headers", "modify_body", "scripts"):
        assert options[name] == []
    for name in ("proxyauth", "upstream_auth", "connect_addr", "save_stream_file"):
        assert options[name] is None
    assert set(expected_options(_config())) == set(options) | set(core_options(_config()))


def test_read_back_matches() -> None:
    expected = expected_options(_config())
    actual: dict[str, Any] = {
        name: tuple(value) if isinstance(value, list) else value for name, value in expected.items()
    }

    assert option_problems(actual.__getitem__, expected) == ()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("connection_strategy", "eager"),
        ("upstream_cert", True),
        ("rawtcp", True),
        ("websocket", True),
        ("http2", True),
        ("ignore_hosts", [".*"]),
        ("tcp_hosts", [".*"]),
        ("mode", ["regular@0.0.0.0:8080"]),
        ("mode", ["regular@10.89.8.254:8080", "socks5@10.89.8.254:1080"]),
        ("stream_large_bodies", "1m"),
        ("body_size_limit", None),
        ("validate_inbound_headers", False),
        ("ssl_insecure", True),
        ("modify_headers", ["/~q/Host/evil"]),
        ("map_remote", ["|.*|http://evil"]),
        ("connect_addr", "10.89.7.1"),
        ("scripts", ["/tmp/x.py"]),  # noqa: S108
        ("block_global", False),
    ],
)
def test_any_unsafe_value_is_reported(name: str, value: object) -> None:
    expected = expected_options(_config())
    actual = {**expected, name: value}

    assert option_problems(actual.__getitem__, expected) == (name,)


def test_options_that_cannot_be_read_are_problems() -> None:
    expected = expected_options(_config())
    actual = {key: value for key, value in expected.items() if key != "rawtcp"}

    assert option_problems(actual.__getitem__, expected) == ("rawtcp",)
