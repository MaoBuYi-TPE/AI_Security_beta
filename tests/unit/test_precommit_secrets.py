"""pre-commit 的 forbid-secret-files（CSEC-06；T23b-b2，docs/DECISIONS.md §32）。

.gitignore 已排除 secrets/，擋得住一般的 git add，擋不住 git add -f。hook 在 commit 之前擋下
secrets/ 中的任何檔案。實際執行：在暫存的 git repo 中，以只含這個 hook 的設定執行 pre-commit
（language: fail，不需要安裝環境、不連網）。
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG: dict[str, Any] = yaml.safe_load(
    (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
)
HOOK_ID = "forbid-secret-files"
ENV_HOOK_ID = "forbid-env-files"


def _hook(hook_id: str = HOOK_ID) -> dict[str, Any]:
    hooks: list[dict[str, Any]] = [
        hook
        for repo in CONFIG["repos"]
        if repo["repo"] == "local"
        for hook in repo["hooks"]
        if hook["id"] == hook_id
    ]
    assert len(hooks) == 1
    return hooks[0]


@pytest.mark.parametrize(
    ("path", "blocked"),
    [
        ("secrets/db_password", True),
        ("secrets/.secscan-sync-db_password.0123", True),
        ("deploy/secrets/x", True),
        # G1d（安全 A1 的 LOW-3）：macOS 預設的檔案系統不分大小寫（core.ignorecase=true），SECRETS/
        # 就是 secrets/。
        ("SECRETS/db_password", True),
        ("Secrets/db_password", True),
        ("deploy/SeCrEtS/x", True),
        ("src/secscan/cli/secret_files.py", False),
        ("tests/unit/test_secret_files_cli.py", False),
        ("docs/secrets.md", False),
        ("docs/SECRETS.md", False),
        ("my-secrets/x", False),
    ],
)
def test_the_hook_matches_files_under_any_secrets_directory(path: str, blocked: bool) -> None:
    hook = _hook()

    assert hook["language"] == "fail"
    assert bool(re.search(hook["files"], path)) is blocked
    assert "exclude" not in hook


@pytest.mark.parametrize(
    ("path", "blocked"),
    [
        (".env", True),
        ("deploy/.env", True),
        (".env.local", True),
        # G1d：和 secrets/ 同樣不分大小寫。
        (".ENV", True),
        ("deploy/.Env.local", True),
        # 只允許小寫的 .env.example（既有的允許項目）；大小寫變形不在允許清單。
        (".env.example", False),
        ("docs/.env.example", False),
        (".ENV.EXAMPLE", True),
        ("env.py", False),
        ("src/secscan/migrations/env.py", False),
        ("docs/.envrc.md", False),
    ],
)
def test_the_env_hook_ignores_case_but_keeps_the_example(path: str, blocked: bool) -> None:
    hook = _hook(ENV_HOOK_ID)

    assert hook["language"] == "fail"
    matched = bool(re.search(hook["files"], path)) and not re.search(hook["exclude"], path)
    assert matched is blocked


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    git = shutil.which("git")
    assert git is not None, "需要 git"
    # 固定的 git 指令，在 pytest 的暫存 repo 中執行。
    return subprocess.run(  # noqa: S603
        [git, *args],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=_environment(repo),
    )


def _environment(repo: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(repo),
        "LC_ALL": "C.UTF-8",
        "PRE_COMMIT_HOME": str(repo / ".pre-commit-cache"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }


def _run_hook(repo: Path, path: str) -> subprocess.CompletedProcess[str]:
    # 固定的 pre-commit（venv 中的模組），只執行這一個 hook。
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pre_commit", "run", HOOK_ID, "--files", path],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=_environment(repo),
    )


def _run_staged(repo: Path) -> subprocess.CompletedProcess[str]:
    """不指定檔案：pre-commit 檢查 staging 中的檔案（git commit 時的情況）。"""
    # 固定的 pre-commit（venv 中的模組），執行暫存 repo 的設定中的兩個 hook。
    return subprocess.run(
        [sys.executable, "-m", "pre_commit", "run"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=_environment(repo),
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    config = {"repos": [{"repo": "local", "hooks": [_hook(ENV_HOOK_ID), _hook()]}]}
    (tmp_path / ".pre-commit-config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    (tmp_path / ".gitignore").write_text("**/secrets/\n.env\n", encoding="utf-8")
    assert _git(tmp_path, "init", "-q").returncode == 0
    return tmp_path


def _force_add(repo: Path, path: str, *, ignorecase: str) -> None:
    """假的秘密檔（不是任何真的秘密），以 git add -f 放進 staging；設定檔也要 staged（pre-commit
    的要求）。"""
    assert _git(repo, "config", "core.ignorecase", ignorecase).returncode == 0
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("not-a-real-secret-0004", encoding="ascii")
    assert _git(repo, "add", "-f", path).returncode == 0
    assert _git(repo, "add", ".pre-commit-config.yaml", ".gitignore").returncode == 0
    staged = _git(repo, "diff", "--cached", "--name-only").stdout.split()
    assert path in staged


@pytest.mark.parametrize("ignorecase", ["true", "false"])
@pytest.mark.parametrize(
    "path",
    [
        "secrets/db_password",
        "SECRETS/db_password",
        "Secrets/db_password",
        "deploy/SeCrEtS/db_password",
        ".env",
        ".ENV",
        "deploy/.Env.local",
    ],
)
def test_a_force_added_case_variant_is_blocked_at_commit(
    repo: Path, path: str, ignorecase: str
) -> None:
    """G1d（安全 A1 的 LOW-3）：git add -f 放進 staging 的大小寫變形，commit 時被擋下。"""
    _force_add(repo, path, ignorecase=ignorecase)

    result = _run_staged(repo)

    assert result.returncode != 0
    assert "Failed" in result.stdout


@pytest.mark.parametrize("path", [".env.example", "docs/secrets.md", "my-secrets/notes.txt"])
def test_allowed_files_pass_at_commit(repo: Path, path: str) -> None:
    _force_add(repo, path, ignorecase="true")

    result = _run_staged(repo)

    assert result.returncode == 0, result.stdout[-1000:]


def test_a_force_added_secret_file_is_blocked(repo: Path) -> None:
    secret = repo / "secrets" / "db_password"
    secret.parent.mkdir()
    secret.write_text("not-a-real-secret", encoding="ascii")
    assert _git(repo, "add", "-f", "secrets/db_password").returncode == 0

    result = _run_hook(repo, "secrets/db_password")

    assert result.returncode != 0
    assert "secrets/" in result.stdout


def test_other_files_pass(repo: Path) -> None:
    (repo / "notes.txt").write_text("ok", encoding="ascii")
    assert _git(repo, "add", "notes.txt").returncode == 0

    assert _run_hook(repo, "notes.txt").returncode == 0
