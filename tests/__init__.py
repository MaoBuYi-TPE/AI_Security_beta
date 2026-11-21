import pytest

# tests/conftest.py 在註冊 plugin 之前就 import tests.live_session（授權的 live 測試保留的變數）：
# 先登記，pytest 才能改寫它的 assert（否則出現 PytestAssertRewriteWarning）。
pytest.register_assert_rewrite("tests.live_session")
