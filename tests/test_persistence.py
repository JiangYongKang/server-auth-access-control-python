"""进程重启语义：用新的 store/service 实例重新加载同一磁盘文件。"""
from __future__ import annotations

import logging

import pytest

from app.auth.errors import (
    InvalidCredentialsError,
    LoginRateLimitedError,
    RefreshFamilyRevokedError,
    RefreshTokenConsumedError,
)
from app.auth.rate_limit import RateLimiter
from app.auth.service import AuthService
from app.auth.store import JsonStore
from tests.conftest import T0, make_service

logger = logging.getLogger("test.persistence")


def restart(config):
    """模拟进程重启：重新从磁盘加载。"""
    store = JsonStore(config.db_path)
    svc = AuthService(config, store, RateLimiter(store))
    logger.info("restart: reloaded store from %s", config.db_path)
    return svc


def test_family_revocation_survives_restart(config, service, tokens):
    rotated = service.refresh(tokens.refresh_token, now=T0 + 10)
    with pytest.raises(RefreshTokenConsumedError):
        service.refresh(tokens.refresh_token, now=T0 + 20)
    logger.info("input: family revoked before restart; now restarting")

    svc2 = restart(config)
    with pytest.raises(RefreshFamilyRevokedError) as exc:
        svc2.refresh(rotated.refresh_token, now=T0 + 30)
    logger.info("decision after restart: %s", exc.value.error_code.value)
    # 旧令牌仍是 consumed 原因（推进到新的失败窗口，避免与刷新限流原因叠加）
    with pytest.raises(RefreshTokenConsumedError):
        svc2.refresh(tokens.refresh_token, now=T0 + config.failure_window_seconds + 100)


def test_login_lockout_survives_restart(config, service):
    # 前 2 次为凭据错误，第 3 次失败把计数推到阈值（login_max_failures=3）-> 锁定
    for i in range(2):
        with pytest.raises(InvalidCredentialsError):
            service.login("bob", "wrong-password", now=T0 + i)
    with pytest.raises(LoginRateLimitedError):
        service.login("bob", "wrong-password", now=T0 + 2)
    logger.info("input: lockout reached; restarting then using CORRECT password")

    svc2 = restart(config)
    with pytest.raises(LoginRateLimitedError) as exc:
        svc2.login("bob", "bob-password", now=T0 + 50)
    logger.info("decision after restart: %s (correct password still rejected)",
                exc.value.error_code.value)

    # 锁定期结束后正确凭据可用（确定性：推进时间越过锁定窗口）
    svc3 = restart(config)
    issued = svc3.login("bob", "bob-password", now=T0 + 2000)
    assert issued.access_token
    logger.info("decision after lock window: login succeeds")


def test_seed_users_not_duplicated_after_restart(config):
    s1 = make_service(config)
    s2 = restart(config)
    with s2.store:
        assert set(s2.store.db.users) == {"admin", "alice", "bob"}
    logger.info("decision: seed users stable across restarts")


def test_normal_chain_survives_unrelated_restart(config, service, tokens):
    rotated = service.refresh(tokens.refresh_token, now=T0 + 10)
    logger.info("input: legitimate rotation then restart")
    svc2 = restart(config)
    rotated2 = svc2.refresh(rotated.refresh_token, now=T0 + 20)
    assert rotated2.refresh_token
    logger.info("decision: legitimate refresh continues after restart")
