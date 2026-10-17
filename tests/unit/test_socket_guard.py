import socket

import pytest
from pytest_socket import SocketBlockedError


@pytest.mark.filterwarnings("ignore:A test tried to use socket.socket:UserWarning")
def test_tcp_socket_is_blocked_during_tests() -> None:
    """unit/contract 測試不得出網：pytest-socket 必須封鎖 TCP socket。"""
    with pytest.raises(SocketBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
