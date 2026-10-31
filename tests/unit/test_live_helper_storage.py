"""Disposable receiver/site containers must not leave inherited anonymous volumes."""

from unittest.mock import Mock, call

import pytest

from tests.live import guard_support, zap_support


@pytest.mark.parametrize("kind", ["receiver", "site"])
def test_helpers_override_the_image_volume_and_remove_owned_anonymous_volumes(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    docker = Mock(return_value='{"ready": true}')
    if kind == "receiver":
        monkeypatch.setattr(guard_support, "docker", docker)
        receiver = guard_support.start_receiver("storage-test", ip="10.89.10.200")
        name = receiver.container
        guard_support.stop_receiver(receiver)
    else:
        monkeypatch.setattr(zap_support, "docker", docker)
        site = zap_support.start_site("storage-test", ip="10.89.10.200", alias="storage-test")
        name = site.container
        zap_support.stop_site(site)

    assert docker.call_args_list[0] == call("rm", "-f", "-v", name, check=False)
    assert docker.call_args_list[-1] == call("rm", "-f", "-v", name, check=False)
    run = docker.call_args_list[1].args
    assert run[0] == "run"
    assert run[run.index("--tmpfs") + 1] == "/home/mitmproxy/.mitmproxy:size=1m,mode=0700"
