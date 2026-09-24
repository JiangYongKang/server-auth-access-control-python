"""并发场景：同一刷新令牌并发轮换只有一个成功；并发越权计数不丢失。"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.auth.errors import (
    ErrorCode,
    RefreshConcurrentError,
    RefreshTokenConsumedError,
    RefreshFamilyRevokedError,
)
from tests.conftest import T0

logger = logging.getLogger("test.concurrency")


def test_concurrent_refresh_only_one_succeeds(service, tokens):
    outcomes = []
    barrier = threading.Barrier(8)

    def worker(i):
        barrier.wait()
        try:
            issued = service.refresh(tokens.refresh_token, now=T0 + 1)
            outcomes.append((i, "ok", issued.refresh_token[:12]))
        except RefreshConcurrentError as exc:
            outcomes.append((i, exc.error_code.value, None))
        except Exception as exc:  # pragma: no cover - 不应出现其他结果
            outcomes.append((i, type(exc).__name__, None))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))

    ok = [o for o in outcomes if o[1] == "ok"]
    concurrent = [o for o in outcomes if o[1] == ErrorCode.REFRESH_CONCURRENT.value]
    logger.info("input: 8 concurrent refreshes of the same token; decision: ok=%d concurrent=%d",
                len(ok), len(concurrent))
    assert len(ok) == 1, outcomes
    assert len(concurrent) == 7, outcomes


def test_concurrent_refresh_does_not_falsely_revoke_family(service, tokens):
    # 被拒的并发请求是“并发冲突”，不是重放攻击：赢家拿到的新令牌必须仍可正常轮换
    outcomes = []
    barrier = threading.Barrier(2)

    def worker():
        barrier.wait()
        try:
            outcomes.append(("ok", service.refresh(tokens.refresh_token, now=T0 + 1)))
        except RefreshConcurrentError:
            outcomes.append(("concurrent", None))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winner = next(o[1] for o in outcomes if o[0] == "ok")
    logger.info("input: use winner's new token; concurrent losers must not poison family")
    second = service.refresh(winner.refresh_token, now=T0 + 2)
    assert second.refresh_token != winner.refresh_token
    logger.info("decision: winner chain continues; no false family revocation")


def test_concurrent_replay_still_revokes_family(service, tokens):
    rotated = service.refresh(tokens.refresh_token, now=T0 + 1)
    outcomes = []
    barrier = threading.Barrier(2)

    def replay():
        barrier.wait()
        try:
            service.refresh(tokens.refresh_token, now=T0 + 2)
            outcomes.append("ok")
        except (RefreshTokenConsumedError, RefreshConcurrentError) as exc:
            outcomes.append(exc.error_code.value)
        except Exception as exc:  # pragma: no cover
            outcomes.append(type(exc).__name__)

    threads = [threading.Thread(target=replay) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    logger.info("input: 2 concurrent replays; outcomes=%s", outcomes)
    # 同一 family 并发互斥：恰好一个进入临界区并被识别为重放(consumed)，
    # 另一个得到并发冲突；任何一个都不可能刷新成功
    assert sorted(outcomes) == sorted([
        ErrorCode.REFRESH_TOKEN_CONSUMED.value,
        ErrorCode.REFRESH_CONCURRENT.value,
    ]), outcomes
    # 整个 family 已失效：轮换令牌不可再用
    import pytest

    with pytest.raises(RefreshFamilyRevokedError):
        service.refresh(rotated.refresh_token, now=T0 + 3)
    logger.info("decision: family revoked despite concurrent replays")


def test_concurrent_unauthorized_access_counts_all(service):
    # 并发越权尝试计数必须全部累计（access_max_failures=4），不多不少
    bob = service.login("bob", "bob-password", now=T0)
    barrier = threading.Barrier(4)

    from app.auth.errors import AccessScopeInsufficientError

    errors = []

    def worker():
        barrier.wait()
        try:
            service.authorize(f"Bearer {bob.access_token}", "profile:read", now=T0 + 1)
        except Exception as exc:
            errors.append(type(exc).__name__)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: worker(), range(4)))

    logger.info("input: 4 concurrent scope violations; outcomes=%s", errors)
    # 计数不丢失 => 恰好达到阈值 => 至少出现限流，且无静默放行
    assert "AccessScopeInsufficientError" in errors
    assert set(errors) <= {"AccessScopeInsufficientError", "AccessRateLimitedError"}
    # 紧接着的请求确定进入锁定
    from app.auth.errors import AccessRateLimitedError

    try:
        service.authorize(f"Bearer {bob.access_token}", "profile:read", now=T0 + 2)
        raise AssertionError("expected lock")
    except AccessRateLimitedError:
        logger.info("decision: lock established after concurrent attempts")
