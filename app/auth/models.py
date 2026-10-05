"""认证领域的数据模型与可注入配置。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class User:
    username: str
    password_hash: str
    password_salt: str
    scopes: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class Session:
    """一个登录会话；刷新令牌族（family）绑定到会话。

    一旦检测到已消费令牌被重放，整个会话（family）立即吊销。
    用户主动登出/撤销/超额驱逐同样通过 revoked 标记生效。

    client_label 为客户端登录时自报的设备/客户端标识（可选）。
    last_refresh_at 记录最近一次刷新轮换时间（0.0 表示从未刷新）。
    expires_at 为会话存活截止时间：每次轮换顺延一个刷新令牌周期，
    过期会话不再出现在列表中，并在清理时被移除。
    """

    session_id: str
    username: str
    family_id: str
    issued_jti: str | None = None
    revoked: bool = False
    revoke_reason: str | None = None
    created_at: float = 0.0
    client_label: str | None = None
    last_refresh_at: float = 0.0
    expires_at: float = 0.0


@dataclass
class RefreshTokenRecord:
    """单个刷新令牌的服务端状态。

    刷新轮换时把旧令牌标记 consumed=True；同一 jti 再次出现即为重放。
    """

    jti: str
    family_id: str
    session_id: str
    username: str
    consumed: bool = False
    expires_at: float = 0.0


@dataclass
class AccessTokenClaims:
    sub: str
    jti: str
    session_id: str
    family_id: str
    scopes: list[str]
    iat: float
    exp: float


@dataclass
class IssuedTokens:
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 0
    refresh_expires_in: int = 0
    session_id: str = ""
    # 登录时因会话数量上限被驱逐（撤销）的旧会话 id，按创建时间从旧到新；
    # 为空表示未触发驱逐。调用方可据此明确感知上限处理结果。
    evicted_sessions: list[str] = field(default_factory=list)


@dataclass
class SessionInfo:
    """会话列表中的单条视图（仅本人会话）。"""

    session_id: str
    client_label: str | None
    created_at: float
    last_refresh_at: float
    is_current: bool


@dataclass
class RateLimitState:
    """窗口内失败次数 + 锁定截止时间戳。"""

    failures: int = 0
    locked_until: float = 0.0
    window_start: float = 0.0


@dataclass
class Database:
    users: dict[str, User] = field(default_factory=dict)
    sessions: dict[str, Session] = field(default_factory=dict)
    refresh_tokens: dict[str, RefreshTokenRecord] = field(default_factory=dict)
    rate_limits: dict[str, RateLimitState] = field(default_factory=dict)

    @classmethod
    def empty(cls) -> "Database":
        return cls()

    def to_json(self) -> dict[str, Any]:
        return {
            "version": 1,
            "users": {k: vars(v) for k, v in self.users.items()},
            "sessions": {k: vars(v) for k, v in self.sessions.items()},
            "refresh_tokens": {k: vars(v) for k, v in self.refresh_tokens.items()},
            "rate_limits": {k: vars(v) for k, v in self.rate_limits.items()},
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "Database":
        db = cls.empty()
        for k, v in payload.get("users", {}).items():
            db.users[k] = User(**v)
        for k, v in payload.get("sessions", {}).items():
            db.sessions[k] = Session(**v)
        for k, v in payload.get("refresh_tokens", {}).items():
            db.refresh_tokens[k] = RefreshTokenRecord(**v)
        for k, v in payload.get("rate_limits", {}).items():
            db.rate_limits[k] = RateLimitState(**v)
        return db


@dataclass
class AuthConfig:
    """可注入配置，测试通过缩短时长/调低阈值保证确定性。"""

    secret: str = "bootstrap-dev-secret-change-me"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 14
    login_max_failures: int = 5
    login_lock_seconds: int = 900
    refresh_max_failures: int = 5
    refresh_lock_seconds: int = 900
    access_max_failures: int = 10
    access_lock_seconds: int = 300
    failure_window_seconds: int = 60 * 15
    db_path: str = "data/auth_store.json"
    # 同一用户允许同时存活的会话上限；超过时按创建时间从旧到新驱逐（撤销），
    # 被驱逐会话的访问/刷新令牌立即失效，判定结果对调用方可区分。
    max_active_sessions_per_user: int = 8
