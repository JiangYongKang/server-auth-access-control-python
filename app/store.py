"""JSON 文件持久化存储：进程重启后状态依然成立。"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Session:
    sid: str
    sub: str
    revoked: bool = False
    refresh_hash: str = ""
    refresh_exp: int = 0
    # 已消费（轮换掉）的刷新令牌散列：保留用于重放检测
    consumed_hashes: list[str] = field(default_factory=list)


@dataclass
class UserRecord:
    sub: str
    password_hash: str
    salt: str
    scopes: list[str] = field(default_factory=list)


class Store:
    """线程安全 + 原子落盘的 JSON 存储。

    所有变更在单个 RLock 下完成并立即原子写盘，
    因此并发刷新只有一个能成功，且重启后状态可复现。
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._users: dict[str, UserRecord] = {}
        self._sessions: dict[str, Session] = {}
        self._refresh_index: dict[str, str] = {}  # refresh_hash -> sid
        self._events: dict[str, list[int]] = {}  # 频次限制事件时间戳
        self._load()

    # --- 持久化 ---
    def _load(self) -> None:
        if not self._path.exists():
            return
        data = json.loads(self._path.read_text(encoding="utf-8"))
        self._users = {k: UserRecord(**v) for k, v in data.get("users", {}).items()}
        self._sessions = {k: Session(**v) for k, v in data.get("sessions", {}).items()}
        self._events = {k: list(v) for k, v in data.get("events", {}).items()}
        self._refresh_index = {}
        for s in self._sessions.values():
            for h in [*s.consumed_hashes, s.refresh_hash]:
                if h:
                    self._refresh_index[h] = s.sid

    def _flush(self) -> None:
        data = {
            "users": {k: asdict(v) for k, v in self._users.items()},
            "sessions": {k: asdict(v) for k, v in self._sessions.items()},
            "events": self._events,
        }
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self._path)  # 原子替换，避免半截文件

    # --- 用户 ---
    def put_user(self, user: UserRecord) -> None:
        with self._lock:
            self._users[user.sub] = user
            self._flush()

    def get_user(self, sub: str) -> UserRecord | None:
        with self._lock:
            return self._users.get(sub)

    # --- 会话 ---
    def put_session(self, session: Session) -> None:
        with self._lock:
            # 当前 + 已消费的散列都保留在索引中（重放检测需要解析旧令牌）
            keep = set(session.consumed_hashes) | ({session.refresh_hash} if session.refresh_hash else set())
            stale = [h for h, sid in self._refresh_index.items()
                     if sid == session.sid and h not in keep]
            for h in stale:
                del self._refresh_index[h]
            self._sessions[session.sid] = session
            for h in keep:
                self._refresh_index[h] = session.sid
            self._flush()

    def get_session(self, sid: str) -> Session | None:
        with self._lock:
            return self._sessions.get(sid)

    def find_session_by_refresh(self, refresh_hash: str) -> Session | None:
        with self._lock:
            sid = self._refresh_index.get(refresh_hash)
            return self._sessions.get(sid) if sid else None

    # --- 频次限制事件 ---
    def record_event(self, key: str, now: int, window: int) -> int:
        """记录一次事件并返回窗口内事件总数。"""
        with self._lock:
            events = [t for t in self._events.get(key, []) if t > now - window]
            events.append(now)
            self._events[key] = events
            self._flush()
            return len(events)

    def count_events(self, key: str, now: int, window: int) -> int:
        with self._lock:
            return sum(1 for t in self._events.get(key, []) if t > now - window)

    def clear_events(self, key: str) -> None:
        with self._lock:
            if key in self._events:
                del self._events[key]
                self._flush()
