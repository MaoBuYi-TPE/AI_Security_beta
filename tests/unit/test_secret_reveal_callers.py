"""API 不解密目標的 secret（docs/DECISIONS.md §12.2）：src 中沒有任何模組呼叫 SecretCipher.reveal。

secret 只寫不讀：新版本沿用 secret 時直接複製密文，金鑰換版用 rotate（不回傳明文）。M2 的 runner
要把 secret 送往被測目標時，會是唯一的呼叫者；屆時把它加進允許的清單。
"""

from tests.unit.source_support import modules_using


def test_no_module_reveals_target_secrets() -> None:
    assert modules_using("reveal") == set()
