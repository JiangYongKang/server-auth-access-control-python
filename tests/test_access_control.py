"""基于作用域的访问控制、默认拒绝与可区分失败原因。"""
from __future__ import annotations

import logging

import pytest

from app.auth.errors import (
    AccessRateLimitedError,
    AccessScopeInsufficientError,
    AccessTokenExpiredError,
    AccessTokenForgeryError,
    AccessTokenMalformedError,
    AccessTokenMissingError,
    AccessTokenSignatureInvalidError,
    ErrorCode,
)
from app.auth.security import _b64e
from tests.conftest import T0

logger = logging.getLogger("test.access")


def test_allow_with_required_scope(service, tokens):
    logger.info("input: scope=profile:read, granted=%s", ["profile:read"])
    subject = service.authorize(f"Bearer {tokens.access_token}", "profile:read", now=T0)
    logger.info("decision: ALLOW subject=%s", subject)
    assert subject == "alice"


def test_default_deny_when_scope_missing(service, tokens):
    # alice 只有 profile:read，请求 admin:action 必须被拒
    logger.info("input: required=admin:action granted=%s", ["profile:read"])
    with pytest.raises(AccessScopeInsufficientError) as exc:
        service.authorize(f"Bearer {tokens.access_token}", "admin:action", now=T0)
    logger.info("decision: DENY reason=%s", exc.value.error_code.value)
    assert exc.value.error_code is ErrorCode.ACCESS_SCOPE_INSUFFICIENT


def test_user_with_no_scopes_is_denied(service):
    empty = service.login("bob", "bob-password", now=T0)
    logger.info("input: bob scopes=%s requests profile:read", [])
    with pytest.raises(AccessScopeInsufficientError):
        service.authorize(f"Bearer {empty.access_token}", "profile:read", now=T0)
    logger.info("decision: DENY bob (no scopes)")


@pytest.mark.parametrize(
    "header_factory,expected,label",
    [
        (lambda t, s: None, AccessTokenMissingError, "missing header"),
        (lambda t, s: "Bearer " + _b64e(b'{"alg":"none"}') + "." + _b64e(b"{}") + ".sig",
         AccessTokenForgeryError, "three-segment jwt forgery"),
        (lambda t, s: "Bearer shape-forgery", AccessTokenForgeryError, "wrong shape"),
        (lambda t, s: "Bearer garbage.token", AccessTokenMalformedError, "undecodable body"),
        (lambda t, s: "Bearer !!!.!!!", AccessTokenMalformedError, "bad base64"),
        (lambda t, s: "Bearer " + t[:-4] + "XXXX",
         AccessTokenSignatureInvalidError, "tampered signature"),
        (lambda t, s: "Malformed " + t, AccessTokenMalformedError, "bad scheme"),
    ],
)
def test_failure_reasons_are_distinguishable(service, tokens, header_factory, expected, label):
    header = header_factory(tokens.access_token, service)
    logger.info("input: %s header=%r", label, (header or "")[:40])
    with pytest.raises(expected) as exc:
        service.authorize(header, "profile:read", now=T0)
    logger.info("decision: %s -> %s", label, exc.value.error_code.value)


def test_expired_access_token_is_distinct(service, tokens):
    logger.info("input: token exp=%d now=%d", T0 + 100, T0 + 101)
    with pytest.raises(AccessTokenExpiredError) as exc:
        service.authorize(f"Bearer {tokens.access_token}", "profile:read", now=T0 + 101)
    assert exc.value.error_code is ErrorCode.ACCESS_TOKEN_EXPIRED


def test_all_failure_codes_are_pairwise_distinct(service, tokens):
    codes = set()
    probes = [
        (None, AccessTokenMissingError),
        ("Bearer x.y.z", AccessTokenForgeryError),
        ("Bearer garbage.token", AccessTokenMalformedError),
        ("Bearer " + tokens.access_token[:-4] + "XXXX", AccessTokenSignatureInvalidError),
    ]
    for header, etype in probes:
        with pytest.raises(etype) as exc:
            service.authorize(header, "profile:read", now=T0)
        codes.add(exc.value.error_code)
    with pytest.raises(AccessTokenExpiredError) as exc:
        service.authorize(f"Bearer {tokens.access_token}", "profile:read", now=T0 + 101)
    codes.add(exc.value.error_code)
    with pytest.raises(AccessScopeInsufficientError) as exc:
        service.authorize(f"Bearer {tokens.access_token}", "admin:action", now=T0)
    codes.add(exc.value.error_code)
    logger.info("decision: collected distinct codes=%s", sorted(c.value for c in codes))
    assert codes == {
        ErrorCode.ACCESS_TOKEN_MISSING,
        ErrorCode.ACCESS_TOKEN_FORGERY,
        ErrorCode.ACCESS_TOKEN_MALFORMED,
        ErrorCode.ACCESS_TOKEN_SIGNATURE_INVALID,
        ErrorCode.ACCESS_TOKEN_EXPIRED,
        ErrorCode.ACCESS_SCOPE_INSUFFICIENT,
    }


def test_unauthorized_failures_accumulate_and_lock(service, tokens):
    # access_max_failures=4：bob 用有效令牌越权，前 3 次 scope 拒绝，第 4 次限流
    bob = service.login("bob", "bob-password", now=T0)
    for i in range(3):
        with pytest.raises(AccessScopeInsufficientError):
            service.authorize(f"Bearer {bob.access_token}", "profile:read", now=T0 + i)
    logger.info("decision: 3 scope denials recorded")
    with pytest.raises(AccessRateLimitedError) as exc:
        service.authorize(f"Bearer {bob.access_token}", "profile:read", now=T0 + 3)
    logger.info("decision: locked -> %s", exc.value.error_code.value)
    assert exc.value.error_code is ErrorCode.RATE_LIMITED_ACCESS

    # 主体隔离：alice 的请求不受 bob 的锁影响（alice 有该作用域，应放行）
    with pytest.raises(AccessRateLimitedError):
        service.authorize(f"Bearer {bob.access_token}", "profile:read", now=T0 + 5)
    alice_allowed = service.authorize(
        f"Bearer {tokens.access_token}", "profile:read", now=T0 + 5
    )
    logger.info("decision: other subject unaffected, alice=%s", alice_allowed)
    assert alice_allowed == "alice"
