"""fixture app 的記憶體狀態：種子使用者、訂單與 session（T30）。

只用標準函式庫的 sqlite3（guard 映像的 python 內可用）。每個 server 程序一份；單元測試
每個案例建一份新的 State，確保可重現。sqlite 連線在 ThreadingHTTPServer 的多執行緒間共用，
以 check_same_thread=False 加一把鎖保護。

種子使用者的密碼與 secret_note 是刻意可被「過度資料暴露」案例讀出的合成資料；secret_note
內嵌合成金絲雀字串（CANARY_*），讓錄製證據的遮罩有可被 CI grep 的標記
（docs/SECURITY_AND_TESTING.md §8）。
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Any

# 合成金絲雀：只存在於這個 lab 靶機，供遮罩檢查。不是真的秘密。
CANARY_ALICE = "SECSCAN-CANARY-alice-7a3f0d"
CANARY_BOB = "SECSCAN-CANARY-bob-9c2e51"
CANARY_ADMIN = "SECSCAN-CANARY-admin-1b8d44"

_USERS: tuple[tuple[int, str, str, int, str, str], ...] = (
    # id, username, password, is_admin, email, secret_note
    (1, "alice", "alice-pw", 0, "alice@lab.test", CANARY_ALICE),
    (2, "bob", "bob-pw", 0, "bob@lab.test", CANARY_BOB),
    (3, "admin", "admin-pw", 1, "admin@lab.test", CANARY_ADMIN),
)
_ORDERS: tuple[tuple[int, str, str, int], ...] = (
    # id, owner, item, total_cents
    (1001, "alice", "widget", 4200),
    (1002, "bob", "gadget", 9900),
    (1003, "alice", "sprocket", 700),
)
# 固定的 session token，讓測試可重現；token 只在這個 lab 靶機有效。
_SESSIONS: dict[str, str] = {
    "alice-token": "alice",
    "bob-token": "bob",
    "admin-token": "admin",
}

_SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER NOT NULL,
    email TEXT NOT NULL,
    secret_note TEXT NOT NULL
);
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    owner TEXT NOT NULL,
    item TEXT NOT NULL,
    total_cents INTEGER NOT NULL
);
"""


@dataclass
class State:
    """一個 fixture 程序的狀態；不是 frozen（持有 sqlite 連線與 session 表）。"""

    db: sqlite3.Connection
    lock: threading.Lock
    sessions: dict[str, str] = field(default_factory=dict)

    def query(self, sql: str, parameters: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        """執行一段 SQL 並回傳所有列（弱點版會在這裡傳入拼接好的 sql）。"""
        with self.lock:
            cursor = self.db.execute(sql, parameters)
            return list(cursor.fetchall())

    def user_for_token(self, token: str | None) -> str | None:
        if token is None:
            return None
        return self.sessions.get(token)

    def token_for_user(self, username: str) -> str | None:
        for token, user in self.sessions.items():
            if user == username:
                return token
        return None


def new_state() -> State:
    """建立並種好一份新的狀態（記憶體 sqlite）。"""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript(_SCHEMA)
    db.executemany(
        "INSERT INTO users (id, username, password, is_admin, email, secret_note) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        _USERS,
    )
    db.executemany(
        "INSERT INTO orders (id, owner, item, total_cents) VALUES (?, ?, ?, ?)",
        _ORDERS,
    )
    db.commit()
    return State(db=db, lock=threading.Lock(), sessions=dict(_SESSIONS))
