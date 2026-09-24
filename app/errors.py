"""认证与访问控制的可区分失败原因。"""
from __future__ import annotations

from enum import Enum


class FailureReason(str, Enum):
    """所有认证/授权失败的可区分原因。"""

    INVALID_CREDENTIALS = "invalid_credentials"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_MISSING = "token_missing"  # 未提供令牌
    TOKEN_INVALID = "token_invalid"  # 伪造 / 签名无效 / 格式错误
    TOKEN_TYPE_MISMATCH = "token_type_mismatch"
    REFRESH_TOKEN_REUSED = "refresh_token_reused"  # 重放已消费的刷新令牌
    REFRESH_TOKEN_UNKNOWN = "refresh_token_unknown"
    SESSION_REVOKED = "session_revoked"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    RATE_LIMITED = "rate_limited"


class AuthError(Exception):
    """携带可区分失败原因的异常。"""

    def __init__(self, reason: FailureReason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail or reason.value
        super().__init__(self.detail)
