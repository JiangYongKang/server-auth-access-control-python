"""频次限制与失败累积：滑动窗口计数 + 锁定期，状态经 Store 持久化。"""
from __future__ import annotations

from app.errors import AuthError, FailureReason
from app.store import Store


class RateLimiter:
    """同一主体在窗口内失败次数达到阈值后进入锁定期。

    锁定期内的请求被明确拒绝（RATE_LIMITED），而非静默放行；
    计数与锁定标记均写入 Store，进程重启后依然成立。
    """

    def __init__(self, store: Store, *, window: int, max_attempts: int, lockout: int) -> None:
        self._store = store
        self._window = window
        self._max_attempts = max_attempts
        self._lockout = lockout

    @staticmethod
    def _lock_key(key: str) -> str:
        return f"lock:{key}"

    def check(self, key: str, now: int) -> None:
        """超限或处于锁定期则抛 AuthError(RATE_LIMITED)。"""
        if self._store.count_events(self._lock_key(key), now, self._lockout) > 0:
            raise AuthError(FailureReason.RATE_LIMITED, "失败次数过多，主体已锁定")
        if self._store.count_events(key, now, self._window) >= self._max_attempts:
            raise AuthError(FailureReason.RATE_LIMITED, "请求频次超限")

    def record_failure(self, key: str, now: int) -> None:
        """累积一次失败；达到阈值后写入锁定标记。"""
        n = self._store.record_event(key, now, self._window)
        if n >= self._max_attempts:
            self._store.record_event(self._lock_key(key), now, self._lockout)

    def reset(self, key: str) -> None:
        """成功后清零失败计数（不影响已有锁定）。"""
        self._store.clear_events(key)
