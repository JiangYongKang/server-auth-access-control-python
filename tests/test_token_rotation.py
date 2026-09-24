"""刷新令牌轮换、重放检测与会话整体吊销。

每个用例打印输入与判定依据（判定日志由 app.auth logger 在 INFO 级输出）。
"""
from __future__ import annotations

import logging

import pytest

from app.auth.errors import (
    ErrorCode,
    RefreshFamilyRevokedError,
    RefreshRateLimitedError,
    RefreshTokenConsumedError,
    RefreshTokenExpiredError,
    RefreshTokenInvalidError,
)
from tests.conftest import T0

logger = logging.getLogger("test.rotation")


def test_refresh_rotates_and_invalidates_old_token(service, tokens):
    logger.info("input: old_refresh_token=%s...", tokens.refresh_token[:16])
    rotated = service.refresh(tokens.refresh_token, now=T0 + 10)
    logger.info("decision: rotation succeeded, new token issued; old must be consumed")

    assert rotated.access_token != tokens.access_token
    assert rotated.refresh_token != tokens.refresh_token

    with pytest.raises(RefreshTokenConsumedError) as exc:
        service.refresh(tokens.refresh_token, now=T0 + 20)
    logger.info("decision: replay of old token -> %s", exc.value.error_code.value)
    assert exc.value.error_code is ErrorCode.REFRESH_TOKEN_CONSUMED


def test_replay_revokes_entire_family(service, tokens):
    rotated = service.refresh(tokens.refresh_token, now=T0 + 10)
    logger.info("input: replay old token to force family revocation")

    with pytest.raises(RefreshTokenConsumedError):
        service.refresh(tokens.refresh_token, now=T0 + 20)

    # 攻击者/合法用户手中的新刷新令牌同样不可用，且原因可区分
    with pytest.raises(RefreshFamilyRevokedError) as exc:
        service.refresh(rotated.refresh_token, now=T0 + 30)
    logger.info("decision: newest token after replay -> %s", exc.value.error_code.value)
    assert exc.value.error_code is ErrorCode.REFRESH_FAMILY_REVOKED

    # 连续非法尝试累积到阈值（refresh_max_failures=3）后转为限流原因，
    # 不会静默放行：此处已发生 2 次（重放+族吊销），再来 1 次即限流
    with pytest.raises(RefreshRateLimitedError) as exc2:
        service.refresh(rotated.refresh_token, now=T0 + 40)
    logger.info("decision: repeated attempts -> %s", exc2.value.error_code.value)
    assert exc2.value.error_code is ErrorCode.RATE_LIMITED_REFRESH


def test_consumed_and_family_revoked_are_distinct(service, tokens):
    rotated = service.refresh(tokens.refresh_token, now=T0 + 10)
    # 重放（失败 #1）-> 旧令牌得到 consumed
    try:
        service.refresh(tokens.refresh_token, now=T0 + 20)
    except RefreshTokenConsumedError as e:
        old_err = e
    # 紧接着的轮换后新令牌 -> family_revoked（失败 #2，尚未到限流阈值 #3）
    try:
        service.refresh(rotated.refresh_token, now=T0 + 22)
    except RefreshFamilyRevokedError as e:
        new_err = e
    logger.info("decision: old=%s new=%s (must differ)",
                old_err.error_code.value, new_err.error_code.value)
    assert old_err.error_code != new_err.error_code


def test_refresh_token_expiry_is_distinct(service, tokens):
    # 在过期时刻之后刷新 -> expired，而非 invalid/consumed
    with pytest.raises(RefreshTokenExpiredError) as exc:
        service.refresh(tokens.refresh_token, now=T0 + 1001)
    logger.info("decision: expired refresh -> %s", exc.value.error_code.value)
    assert exc.value.error_code is ErrorCode.REFRESH_TOKEN_EXPIRED


def test_unknown_and_forged_refresh_tokens_are_invalid(service):
    for bad in ("", "not-a-token", "a.b.c", "aaa.bbb"):
        logger.info("input: forged/garbage refresh token %r", bad)
        with pytest.raises(RefreshTokenInvalidError) as exc:
            service.refresh(bad, now=T0)
        assert exc.value.error_code is ErrorCode.REFRESH_TOKEN_INVALID
    logger.info("decision: all garbage refresh tokens -> refresh_token_invalid")


def test_rotation_supports_chained_use(service, tokens):
    # 正常链：连续轮换都成功；一旦回用任意旧令牌则全族失效
    chain = [tokens.refresh_token]
    current = tokens
    for i in range(1, 4):
        current = service.refresh(current.refresh_token, now=T0 + i)
        chain.append(current.refresh_token)
    logger.info("input: chain length=%d, reusing oldest token", len(chain))

    with pytest.raises(RefreshTokenConsumedError):
        service.refresh(chain[0], now=T0 + 10)

    with pytest.raises(RefreshFamilyRevokedError):
        service.refresh(chain[-1], now=T0 + 11)
