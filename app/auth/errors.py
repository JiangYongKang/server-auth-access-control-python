"""认证与访问控制领域的错误码定义与异常类型。

所有失败原因都有互不相同的错误码，便于测试精确断言，
也便于调用方在不泄露资源存在性的前提下区分失败原因。
"""
from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    # 凭据 / 登录阶段
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"
    RATE_LIMITED_LOGIN = "rate_limited_login"
    # 刷新令牌阶段
    REFRESH_TOKEN_INVALID = "refresh_token_invalid"
    REFRESH_TOKEN_EXPIRED = "refresh_token_expired"
    REFRESH_TOKEN_CONSUMED = "refresh_token_consumed"
    REFRESH_FAMILY_REVOKED = "refresh_family_revoked"
    RATE_LIMITED_REFRESH = "rate_limited_refresh"
    REFRESH_CONCURRENT = "refresh_concurrent"
    # 访问令牌阶段
    ACCESS_TOKEN_MISSING = "access_token_missing"
    ACCESS_TOKEN_MALFORMED = "access_token_malformed"
    ACCESS_TOKEN_SIGNATURE_INVALID = "access_token_signature_invalid"
    ACCESS_TOKEN_EXPIRED = "access_token_expired"
    ACCESS_TOKEN_FORGERY = "access_token_forgery"
    ACCESS_SCOPE_INSUFFICIENT = "access_scope_insufficient"
    RATE_LIMITED_ACCESS = "rate_limited_access"


class AuthError(Exception):
    """所有认证失败的统一基类。"""

    error_code: ErrorCode = ErrorCode.INVALID_CREDENTIALS
    message: str = "authentication failed"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.message)
        if message is not None:
            self.message = message


class InvalidCredentialsError(AuthError):
    error_code = ErrorCode.INVALID_CREDENTIALS
    message = "username or password is incorrect"


class AccountLockedError(AuthError):
    error_code = ErrorCode.ACCOUNT_LOCKED
    message = "account is locked due to repeated failures"


class LoginRateLimitedError(AuthError):
    error_code = ErrorCode.RATE_LIMITED_LOGIN
    message = "too many authentication attempts for this subject"


class RefreshTokenInvalidError(AuthError):
    error_code = ErrorCode.REFRESH_TOKEN_INVALID
    message = "refresh token is invalid"


class RefreshTokenExpiredError(AuthError):
    error_code = ErrorCode.REFRESH_TOKEN_EXPIRED
    message = "refresh token has expired"


class RefreshTokenConsumedError(AuthError):
    error_code = ErrorCode.REFRESH_TOKEN_CONSUMED
    message = "refresh token has already been consumed"


class RefreshFamilyRevokedError(AuthError):
    error_code = ErrorCode.REFRESH_FAMILY_REVOKED
    message = "token family was revoked after a replay was detected"


class RefreshRateLimitedError(AuthError):
    error_code = ErrorCode.RATE_LIMITED_REFRESH
    message = "too many refresh attempts for this subject"


class RefreshConcurrentError(AuthError):
    error_code = ErrorCode.REFRESH_CONCURRENT
    message = "a concurrent refresh of this token family is in progress"


class AccessTokenMissingError(AuthError):
    error_code = ErrorCode.ACCESS_TOKEN_MISSING
    message = "access token is missing"


class AccessTokenMalformedError(AuthError):
    error_code = ErrorCode.ACCESS_TOKEN_MALFORMED
    message = "access token is malformed"


class AccessTokenSignatureInvalidError(AuthError):
    error_code = ErrorCode.ACCESS_TOKEN_SIGNATURE_INVALID
    message = "access token signature is invalid"


class AccessTokenExpiredError(AuthError):
    error_code = ErrorCode.ACCESS_TOKEN_EXPIRED
    message = "access token has expired"


class AccessTokenForgeryError(AuthError):
    error_code = ErrorCode.ACCESS_TOKEN_FORGERY
    message = "access token is a forged non-session token"


class AccessScopeInsufficientError(AuthError):
    error_code = ErrorCode.ACCESS_SCOPE_INSUFFICIENT
    message = "token does not carry the required scope"


class AccessRateLimitedError(AuthError):
    error_code = ErrorCode.RATE_LIMITED_ACCESS
    message = "too many unauthorized attempts from this subject"
