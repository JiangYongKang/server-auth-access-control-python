"""频次限制：固定窗口失败累积 + 阈值锁定。

- 窗口（failure_window_seconds）外的失败计数自动清零重新累计；
- 累计达到 max_failures 后，锁定至 locked_until；
- 状态保存在 Database.rate_limits 中并随每次变更落盘，
  因此锁定在进程重启后依然成立。

调用方必须在持有 store 临界区（``with store``）期间调用本类方法，
以保证“检查 + 计数 + 锁定”跨线程不交叉。
"""
from __future__ import annotations

from app.auth.models import Database, RateLimitState
from app.auth.store import JsonStore


class RateLimiter:
    def __init__(self, store: JsonStore) -> None:
        self.store = store

    @staticmethod
    def login_key(username: str) -> str:
        return f"login:{username}"

    @staticmethod
    def refresh_key(username: str) -> str:
        return f"refresh:{username}"

    @staticmethod
    def access_key(subject: str) -> str:
        return f"access:{subject}"

    def _state(self, db: Database, key: str, now: float, window: int) -> RateLimitState:
        state = db.rate_limits.get(key)
        if state is None:
            state = RateLimitState(failures=0, locked_until=0.0, window_start=now)
            db.rate_limits[key] = state
            return state
        if now - state.window_start >= window:
            # 上一窗口已结束：开始新窗口（旧锁定也随之失效）
            state.failures = 0
            state.locked_until = 0.0
            state.window_start = now
        return state

    def is_locked(self, key: str, window: int, now: float) -> bool:
        db = self.store.db
        state = db.rate_limits.get(key)
        if state is None:
            return False
        state = self._state(db, key, now, window)
        return state.locked_until > now

    def record_failure(
        self,
        key: str,
        max_failures: int,
        lock_seconds: int,
        window: int,
        now: float,
    ) -> RateLimitState:
        db = self.store.db
        state = self._state(db, key, now, window)
        state.failures += 1
        if state.failures >= max_failures:
            state.locked_until = now + lock_seconds
        return state

    def reset(self, key: str) -> None:
        self.store.db.rate_limits.pop(key, None)
