"""tests/live/env_guard.py 清理失敗的診斷檔：不含秘密的識別事實（G1e；G1d 安全審查 B 的 LOW-3）。

診斷檔只供人工排查：程式不讀回內容（preflight 只看檔名），清理的判斷、核對與刪除範圍都不變。內容分成
三類，不混用：

- 所有權紀錄中的值：只在紀錄可信（識別與 Engine 和這次執行相同）時列出，一律標示「紀錄中的值，未必
  已經過 Docker 核對」；
- 這次以 Network ID inspect 核對成功的網路：才標示「已核對」；
- 沒有核對成功的網路：不符、無法核對（inspect 失敗）、沒有核對（Engine 不同）。

紀錄不可信時只輸出程式判斷出來的狀態，不輸出紀錄中的任何值（Network ID、名稱、識別、Engine）。
docker 以有狀態的替身取代（不連 daemon；tests/unit/live_cleanup_fake.py）。
"""

import ast
import hashlib
import os
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from tests.live import env_guard
from tests.live.env_guard import DiagnosticFacts, NetworkCheck, NetworkFact, RecordState
from tests.unit.live_cleanup_fake import (
    ENGINE,
    LAB,
    OTHER,
    OURS,
    OWNER,
    SCAN,
    CleanupDocker,
    _run_dir,
    nid,
    write_record,
)

VERIFIED_MARK = "已核對"
RECORD_VALUE_MARK = "紀錄中的值，未必已經過 Docker 核對"
CANARY_SECRET = "canary-" + hashlib.sha256(b"g1e-disposable-secret").hexdigest()[:24]
# 不可信的紀錄中的 Network ID：出現在診斷檔（含前 12 碼）就代表輸出了不可信的值。
UNTRUSTED_IDS = {
    SCAN: hashlib.sha256(b"g1e-untrusted-scan").hexdigest(),
    LAB: hashlib.sha256(b"g1e-untrusted-lab").hexdigest(),
}


def _directory(tmp_path: Path, networks: dict[str, str] | None = OURS) -> Path:
    directory = _run_dir(tmp_path, networks)
    (directory / "db_password").write_text(CANARY_SECRET, encoding="ascii")
    return directory


def _cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    docker: Any,
    directory: Path,
    *,
    claimed: bool = True,
) -> tuple[int, str]:
    """以 CLI 執行清理，回傳結束碼與唯一的診斷檔（0600）的內容。"""
    monkeypatch.setattr(env_guard, "docker", docker)
    argv = ["cleanup", "--base", str(tmp_path), "--secrets-dir", str(directory)]
    code = env_guard.main([*argv, "--engine", ENGINE, *(["--claimed"] if claimed else [])])
    [path] = tmp_path.glob(f"{env_guard.DIAGNOSTIC_PREFIX}*")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    return code, path.read_text(encoding="utf-8")


def _section(text: str, header: str) -> list[str]:
    """header 開頭的那一段（到下一個不是「- 」開頭的行為止）。"""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(header)), None)
    if start is None:
        return []
    section = []
    for line in lines[start + 1 :]:
        if not line.startswith("- "):
            break
        section.append(line)
    return section


def _assert_common(text: str, tmp_path: Path) -> None:
    """每個診斷檔都有固定的說明與兩行警告；不含拋棄式的秘密與完整的暫存目錄路徑。"""
    assert env_guard.DIAGNOSTIC_NOTICE in text
    for warning in env_guard.DIAGNOSTIC_WARNINGS:
        assert warning in text
    assert len(env_guard.DIAGNOSTIC_WARNINGS) == 2
    assert CANARY_SECRET not in text
    assert str(tmp_path) not in text
    assert "開始時的 Engine ID（recipe 在開始時確認、以 --engine 傳入；" in text
    assert f"）：{ENGINE}" in text


# --------------------------------------------------------------------------- 可信的紀錄


def test_a_claimed_run_lists_the_verified_network_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """取得所有權、兩個網路都以 ID 核對通過，之後 compose down 失敗：列出 Engine ID 與兩個完整的
    Network ID 與名稱，標示已核對。"""
    directory = _directory(tmp_path)

    code, text = _cleanup(tmp_path, monkeypatch, CleanupDocker(fail=["compose down"]), directory)

    assert code == env_guard.EXIT_FAILURE
    _assert_common(text, tmp_path)
    assert f"所有權紀錄：{RecordState.CLAIMED.value}" in text
    assert "recipe 記錄的所有權（--claimed）：有" in text
    assert "清理開始時的 Engine 核對：和開始時相同" in text
    recorded = _section(text, "所有權紀錄中的網路")
    verified = _section(text, "這次以 Network ID 核對成功的網路")
    assert recorded == [f"- {name}：Network ID {OURS[name]}" for name in sorted(OURS)]
    assert verified == [f"- {name}：Network ID {OURS[name]}" for name in sorted(OURS)]
    assert RECORD_VALUE_MARK in text
    assert _section(text, "沒有核對成功的網路") == []
    assert "- compose down -v" in text


def test_only_the_network_that_was_verified_is_marked_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """同一個 Network ID 的標記被改成別的執行（外部變更）：只有另一個網路標示已核對；標記不符的只在
    紀錄中的值與沒有核對成功的網路出現。"""
    directory = _directory(tmp_path)
    docker = CleanupDocker(networks={SCAN: OTHER, LAB: OWNER}, network_ids={SCAN: OURS[SCAN]})

    _, text = _cleanup(tmp_path, monkeypatch, docker, directory)

    assert _section(text, "這次以 Network ID 核對成功的網路") == [
        f"- {LAB}：Network ID {OURS[LAB]}"
    ]
    assert _section(text, "沒有核對成功的網路") == [f"- {SCAN}：{NetworkCheck.MISMATCH.value}"]
    assert f"- {SCAN}：Network ID {OURS[SCAN]}" in _section(text, "所有權紀錄中的網路")
    assert OTHER not in text


TRUSTED_NOT_VERIFIED: dict[str, tuple[dict[str, Any], NetworkCheck, NetworkCheck]] = {
    # 同名同標記、不同的 ID（被換掉）：以紀錄的 ID inspect 找不到（和 daemon 相同）。
    "replaced-with-a-new-id": (
        {"network_ids": {SCAN: nid(SCAN, OWNER, 1), LAB: nid(LAB, OWNER, 1)}},
        NetworkCheck.UNAVAILABLE,
        NetworkCheck.UNAVAILABLE,
    ),
    # 同一個 ID、標記被改成別的執行：inspect 找得到，但標記和紀錄不同。
    "relabelled": (
        {"networks": {SCAN: OTHER, LAB: OTHER}, "network_ids": OURS},
        NetworkCheck.MISMATCH,
        NetworkCheck.MISMATCH,
    ),
    "gone": (
        {"networks": {}, "containers": [], "volumes": {}, "compose_networks": ()},
        NetworkCheck.UNAVAILABLE,
        NetworkCheck.UNAVAILABLE,
    ),
    "inspect-fails": (
        {"fail": ["network inspect"]},
        NetworkCheck.UNAVAILABLE,
        NetworkCheck.UNAVAILABLE,
    ),
    "engine-changed": (
        {"engine_id": "engine-2"},
        NetworkCheck.NOT_CHECKED,
        NetworkCheck.NOT_CHECKED,
    ),
    "one-gone-one-relabelled": (
        {"networks": {SCAN: OTHER}, "network_ids": {SCAN: OURS[SCAN]}},
        NetworkCheck.UNAVAILABLE,
        NetworkCheck.MISMATCH,
    ),
}


@pytest.mark.parametrize("case", sorted(TRUSTED_NOT_VERIFIED))
def test_a_trusted_record_without_a_successful_check_never_says_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """紀錄可信，但網路被換掉、不見了、inspect 失敗或 Engine 不同：紀錄中的值都標示「未必已經過
    Docker 核對」並附上實際的狀態，檔案中不出現「已核對」。"""
    changes, lab, scan = TRUSTED_NOT_VERIFIED[case]
    directory = _directory(tmp_path)

    code, text = _cleanup(tmp_path, monkeypatch, CleanupDocker(**changes), directory)

    assert code == env_guard.EXIT_FAILURE
    _assert_common(text, tmp_path)
    assert VERIFIED_MARK not in text
    assert f"所有權紀錄：{RecordState.CLAIMED.value}" in text
    assert RECORD_VALUE_MARK in text
    assert _section(text, "所有權紀錄中的網路") == [
        f"- {name}：Network ID {OURS[name]}" for name in sorted(OURS)
    ]
    assert _section(text, "這次以 Network ID 核對成功的網路") == []
    assert _section(text, "沒有核對成功的網路") == [
        f"- {LAB}：{lab.value}",
        f"- {SCAN}：{scan.value}",
    ]


def test_an_engine_change_at_the_start_of_the_cleanup_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _directory(tmp_path)

    _, text = _cleanup(tmp_path, monkeypatch, CleanupDocker(engine_id="engine-2"), directory)

    assert "清理開始時的 Engine 核對：不同或無法確認（沒有碰任何 Docker 資源）" in text
    assert "engine-2" not in text


def test_a_partial_record_is_trusted_but_says_it_was_not_claimed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """只建立了一個網路（沒有 claimed）、recipe 也沒有記錄所有權：紀錄可信，狀態寫明沒有 claimed；
    網路上還有別人的容器，清理失敗。"""
    directory = _directory(tmp_path, {SCAN: OURS[SCAN]})
    docker = CleanupDocker(networks={SCAN: OWNER}, volumes={}, compose_networks=())

    _, text = _cleanup(tmp_path, monkeypatch, docker, directory, claimed=False)

    assert f"所有權紀錄：{RecordState.PARTIAL.value}" in text
    assert "recipe 記錄的所有權（--claimed）：沒有" in text
    assert _section(text, "所有權紀錄中的網路") == [f"- {SCAN}：Network ID {OURS[SCAN]}"]


# --------------------------------------------------------------------------- 不可信或沒有紀錄


def _untrusted(directory: Path, tmp_path: Path, kind: str) -> None:
    record = directory / env_guard.CLAIM_FILE
    if kind == "corrupt":
        record.write_text("{" * 3, encoding="utf-8")
    elif kind == "symlink":
        # 連結的目標是一份有效、claimed 的紀錄：跟隨 symlink 就會讀到它的值。
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        write_record(elsewhere, UNTRUSTED_IDS, claimed=True)
        record.symlink_to(elsewhere / env_guard.CLAIM_FILE)
    elif kind == "unreadable":
        write_record(directory, UNTRUSTED_IDS, claimed=True)
        record.chmod(0)
    elif kind == "other-owner":
        changes = {"owner": OTHER, "labels": {env_guard.RUN_LABEL: OTHER}}
        write_record(directory, UNTRUSTED_IDS, claimed=True, changes=changes)
    elif kind == "other-engine":
        write_record(directory, UNTRUSTED_IDS, claimed=True, changes={"engine": "engine-2"})
    else:
        changes = {"labels": {env_guard.RUN_LABEL: OTHER}}
        write_record(directory, UNTRUSTED_IDS, claimed=True, changes=changes)


UNTRUSTED = {
    "corrupt": RecordState.INVALID,
    "unexpected-labels": RecordState.INVALID,
    "symlink": RecordState.UNREADABLE,
    "unreadable": RecordState.UNREADABLE,
    "other-owner": RecordState.OWNER_MISMATCH,
    "other-engine": RecordState.ENGINE_MISMATCH,
}


@pytest.mark.parametrize("kind", sorted(UNTRUSTED))
def test_an_untrusted_record_reports_only_its_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """紀錄不可信：只有程式判斷出來的狀態，沒有紀錄中的任何值（Network ID、網路的名稱、識別、
    Engine）。"""
    directory = _directory(tmp_path, None)
    _untrusted(directory, tmp_path, kind)

    code, text = _cleanup(tmp_path, monkeypatch, CleanupDocker(), directory)

    assert code == env_guard.EXIT_FAILURE
    _assert_common(text, tmp_path)
    assert f"所有權紀錄：{UNTRUSTED[kind].value}" in text
    assert "網路：沒有可信的所有權紀錄，不列出紀錄中的任何值" in text
    leaked = [
        value
        for value in (*UNTRUSTED_IDS.values(), *(item[:12] for item in UNTRUSTED_IDS.values()))
        if value in text
    ]
    assert leaked == []
    assert SCAN not in text
    assert LAB not in text
    assert OTHER not in text
    assert "engine-2" not in text
    assert VERIFIED_MARK not in text
    assert RECORD_VALUE_MARK not in text


def test_a_missing_record_with_a_claim_has_no_network_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _directory(tmp_path, None)

    _, text = _cleanup(tmp_path, monkeypatch, CleanupDocker(), directory)

    assert f"所有權紀錄：{RecordState.ABSENT.value}" in text
    assert "網路：沒有可信的所有權紀錄，不列出紀錄中的任何值" in text
    assert SCAN not in text
    assert VERIFIED_MARK not in text


def test_a_cleanup_without_a_valid_directory_says_the_record_was_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    misplaced = tmp_path / "elsewhere" / OWNER

    _, text = _cleanup(tmp_path, monkeypatch, CleanupDocker(), misplaced)

    assert f"所有權紀錄：{RecordState.NOT_READ.value}" in text
    assert "清理開始時的 Engine 核對：沒有進行或沒有確認" in text
    assert VERIFIED_MARK not in text


# --------------------------------------------------------------------------- 中斷與錯誤的路徑


INTERRUPTIONS: dict[str, tuple[type[BaseException], str]] = {
    "keyboard-interrupt": (KeyboardInterrupt, "清理被中斷"),
    "os-error": (PermissionError, "清理無法存取檔案（PermissionError）"),
    "unexpected-error": (TypeError, "清理發生未預期的錯誤（TypeError）"),
}


@pytest.mark.parametrize("case", sorted(INTERRUPTIONS))
def test_an_interrupted_cleanup_writes_only_the_facts_it_was_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """中斷的路徑只寫參數中已知的事實（Engine ID、claimed）與「沒有確認」，不列出網路；拋棄式目錄
    還在，裡面的秘密也不寫入。"""
    error, reason = INTERRUPTIONS[case]
    directory = _directory(tmp_path)
    docker = CleanupDocker()

    def interrupted(arguments: Sequence[str]) -> str:
        if "down" in arguments:
            raise error
        return docker(arguments)

    monkeypatch.setattr(env_guard, "docker", interrupted)
    argv = ["cleanup", "--base", str(tmp_path), "--secrets-dir", str(directory)]
    if case == "unexpected-error":
        with pytest.raises(TypeError):
            env_guard.main([*argv, "--engine", ENGINE, "--claimed"])
    else:
        assert env_guard.main([*argv, "--engine", ENGINE, "--claimed"]) == env_guard.EXIT_FAILURE

    [path] = tmp_path.glob(f"{env_guard.DIAGNOSTIC_PREFIX}*")
    text = path.read_text(encoding="utf-8")
    assert directory.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    _assert_common(text, tmp_path)
    assert reason in text
    assert f"所有權紀錄：{RecordState.INTERRUPTED.value}" in text
    assert "recipe 記錄的所有權（--claimed）：有" in text
    assert all(network_id not in text for network_id in OURS.values())
    assert VERIFIED_MARK not in text


def test_a_failed_write_is_reported_and_the_empty_file_still_blocks_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """寫入失敗（write 的 OSError）：照舊回報寫不進去；mkstemp 建立的檔名仍讓下一次的 preflight
    拒絕執行（診斷檔在清理的判斷都結束之後才寫，寫入失敗不會影響刪除了什麼）。"""
    failing = tmp_path / "failing"
    failing.mkdir()
    docker = CleanupDocker(fail=["compose down"])
    real_fdopen = os.fdopen

    def fdopen(descriptor: int, *args: Any, **kwargs: Any) -> Any:
        stream = real_fdopen(descriptor, *args, **kwargs)

        def write(_text: str) -> int:
            raise OSError(5, "Input/output error")

        stream.write = write
        return stream

    monkeypatch.setattr(os, "fdopen", fdopen)
    monkeypatch.setattr(env_guard, "docker", docker)
    directory = _directory(failing)
    argv = ["cleanup", "--base", str(failing), "--secrets-dir", str(directory)]
    code = env_guard.main([*argv, "--engine", ENGINE, "--claimed"])
    monkeypatch.undo()

    err = capsys.readouterr().err
    assert code == env_guard.EXIT_FAILURE
    assert "無法寫入診斷檔（Input/output error）" in err
    diagnostics = list(failing.glob(f"{env_guard.DIAGNOSTIC_PREFIX}*"))
    assert [path.stat().st_size for path in diagnostics] == [0]
    with pytest.raises(env_guard.GuardError, match="診斷檔"):
        env_guard.preflight(failing, CleanupDocker(networks={}, containers=[], volumes={}))


# --------------------------------------------------------------------------- 格式與不變的保證


def _written(tmp_path: Path, secrets_dir: str, failures: list[str], facts: Any) -> str:
    path = env_guard.write_diagnostic(tmp_path, secrets_dir, failures, facts)
    text = path.read_text(encoding="utf-8")
    path.unlink()
    return text


def test_an_engine_id_with_an_unexpected_shape_is_not_written(tmp_path: Path) -> None:
    """--engine 的值只在形狀安全時寫入（換行、空白等不寫：避免偽造其他行）。"""
    facts = DiagnosticFacts(f"{ENGINE}\n{VERIFIED_MARK}", True, RecordState.INTERRUPTED)

    text = _written(tmp_path, str(tmp_path / OWNER), ["x"], facts)

    assert "（格式不符，不輸出）" in text
    assert VERIFIED_MARK not in text


ENGINE_SHAPES = {
    # 虛構的值：UUID 形式（Docker 23 起）、舊式以冒號分組的 12 組 4 碼（59 字元）、長度的邊界。
    "uuid": ("123e4567-e89b-12d3-a456-426614174000", True),
    "legacy": (":".join(["ABCD"] * 12), True),
    "128-characters": ("a" * 128, True),
    "129-characters": ("a" * 129, False),
    "leading-dash": ("-engine", False),
    "space": ("engine 1", False),
    "non-ascii": ("engine-\uff11", False),
    "empty": ("", False),
}


@pytest.mark.parametrize("case", sorted(ENGINE_SHAPES))
def test_the_engine_id_shape(tmp_path: Path, case: str) -> None:
    value, shown = ENGINE_SHAPES[case]
    facts = DiagnosticFacts(value, False, RecordState.INTERRUPTED)

    text = _written(tmp_path, str(tmp_path / OWNER), ["x"], facts)

    line = next(item for item in text.splitlines() if item.startswith("開始時的 Engine ID"))
    assert line.endswith(f"：{value}" if shown else "：（格式不符，不輸出）")


@pytest.mark.parametrize(
    ("secrets_dir", "shown"),
    [
        (f"/base/{OWNER}", OWNER),
        (f"/base/{OWNER}/", OWNER),
        ("", "（沒有）"),
        (f"/base/{OWNER}\n這次以 Network ID 核對成功的網路", "（格式不符，不輸出）"),
        ("/base/not-a-run", "（格式不符，不輸出）"),
    ],
    ids=["run-id", "trailing-slash", "empty", "newline", "other-name"],
)
def test_the_disposable_directory_name_is_written_only_when_it_has_the_run_id_shape(
    tmp_path: Path, secrets_dir: str, shown: str
) -> None:
    """G1e 的安全審查 LOW-1：--secrets-dir 也是外部的參數，名稱含換行時不能偽造其他行。"""
    text = _written(tmp_path, secrets_dir, ["x"], None)

    assert f"拋棄式目錄：{shown}\n" in text
    assert not any(line.startswith("這次以 Network ID") for line in text.splitlines())


def test_failure_lines_cannot_forge_other_lines(tmp_path: Path) -> None:
    """失敗的步驟可能含外部來的字串：換行、CR、行分隔字元與雙向控制字元都換成 ?，不會變成新的一行
    （G1e 的安全審查 INFO-4）。"""
    forged = f"x\n這次以 Network ID 核對成功的網路（{VERIFIED_MARK}）：\r- {SCAN}\u2028y\u202ez"
    facts = DiagnosticFacts(ENGINE, True, RecordState.INTERRUPTED)

    text = _written(tmp_path, str(tmp_path / OWNER), [forged], facts)

    lines = text.splitlines()
    assert not any(line.startswith("這次以 Network ID") for line in lines)
    assert not any(line.startswith(f"- {SCAN}") for line in lines)
    assert "\r" not in text
    assert "\u2028" not in text
    assert "\u202e" not in text
    assert f"- x?這次以 Network ID 核對成功的網路（{VERIFIED_MARK}）：?- {SCAN}?y?z" in lines


def test_the_fixed_text_does_not_contain_a_failure_step() -> None:
    """固定的說明與警告不含「compose down -v」：既有的測試以這個子字串確認失敗的步驟有寫出
    （G1e 的程式碼審查 LOW-1）。"""
    for text in (env_guard.DIAGNOSTIC_NOTICE, *env_guard.DIAGNOSTIC_WARNINGS):
        assert "compose down -v" not in text


BREAKING_CHARACTERS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029\x1b\u202e\ufeff"


@pytest.mark.parametrize("character", list(BREAKING_CHARACTERS), ids=lambda c: f"U+{ord(c):04X}")
def test_every_line_breaking_or_control_character_is_escaped(
    tmp_path: Path, character: str
) -> None:
    """str.splitlines() 的所有分行字元、ESC、雙向控制字元與 BOM：失敗的步驟仍是同一行，行數和只有
    一般文字時相同（G1e 的確認審查 INFO-1）。"""
    facts = DiagnosticFacts(ENGINE, True, RecordState.INTERRUPTED)
    plain = _written(tmp_path, str(tmp_path / OWNER), ["a-b"], facts)

    text = _written(tmp_path, str(tmp_path / OWNER), [f"a{character}b"], facts)

    assert len(text.splitlines()) == len(plain.splitlines())
    assert "- a?b" in text.splitlines()


def test_no_written_fact_contains_a_failure_step(tmp_path: Path) -> None:
    """每個狀態、核對結果與 Engine 的核對寫出的全文都不含「compose down -v」：只有失敗的步驟會寫出
    它（G1e 的確認審查 INFO-2）。"""
    for state in RecordState:
        for check in NetworkCheck:
            for confirmed in (True, False, None):
                networks = (NetworkFact(SCAN, OURS[SCAN], check),)
                facts = DiagnosticFacts(ENGINE, True, state, confirmed, networks)
                text = _written(tmp_path, str(tmp_path / OWNER), [], facts)
                assert "compose down -v" not in text
    assert "compose down -v" not in _written(tmp_path, "", [], None)


def test_networks_are_never_written_for_an_untrusted_state(tmp_path: Path) -> None:
    """縱深防禦：即使事實中帶有網路，紀錄不可信的狀態下也不寫出。"""
    networks = (NetworkFact(SCAN, OURS[SCAN], NetworkCheck.VERIFIED),)
    for state in RecordState:
        if state in env_guard.TRUSTED_RECORDS:
            continue
        facts = DiagnosticFacts(ENGINE, True, state, True, networks)

        path = env_guard.write_diagnostic(tmp_path, str(tmp_path / OWNER), ["x"], facts)

        text = path.read_text(encoding="utf-8")
        path.unlink()
        assert OURS[SCAN] not in text
        assert VERIFIED_MARK not in text


def test_only_write_diagnostic_and_the_preflight_glob_touch_diagnostic_files() -> None:
    """靜態的預警（不是證明）：env_guard.py 中只有 write_diagnostic（建立）與 preflight（只看檔名）
    參照診斷檔的前綴；前綴的字面字串只出現在常數的定義；preflight 不開啟、不讀取任何檔案。"""
    source = Path(env_guard.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "cleanup-failed" in node.value
    ]
    assert literals == [env_guard.DIAGNOSTIC_PREFIX]
    users = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        names = {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
        if "DIAGNOSTIC_PREFIX" in names:
            users.add(node.name)
    [preflight] = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "preflight"
    ]
    called = {
        item.func.attr if isinstance(item.func, ast.Attribute) else getattr(item.func, "id", "")
        for item in ast.walk(preflight)
        if isinstance(item, ast.Call)
    }

    assert users == {"write_diagnostic", "preflight"}
    assert called.isdisjoint({"open", "read_text", "read_bytes", "fdopen", "read"})


@pytest.mark.parametrize(
    "content",
    [
        "",
        f"已核對\n- {SCAN}：Network ID {OURS[SCAN]}\n",
        '{"engine": "engine-1", "claimed": true}',
    ],
    ids=["empty", "forged-verified-line", "forged-record-json"],
)
def test_preflight_depends_only_on_the_diagnostic_file_name(tmp_path: Path, content: str) -> None:
    """行為上的確認（G1e 的安全審查 INFO-1）：診斷檔的內容不影響 preflight，偽造的內容和空檔的
    結果完全相同（都以同一個訊息拒絕執行）。"""
    (tmp_path / f"{env_guard.DIAGNOSTIC_PREFIX}abc.txt").write_text(content, encoding="utf-8")
    clean = CleanupDocker(networks={}, containers=[], volumes={}, compose_networks=())

    with pytest.raises(env_guard.GuardError) as refused:
        env_guard.preflight(tmp_path, clean)

    assert str(refused.value) == (
        f"上一次的清理失敗（{tmp_path} 中有 1 個診斷檔）：確認並處理之後刪除診斷檔再執行"
    )
