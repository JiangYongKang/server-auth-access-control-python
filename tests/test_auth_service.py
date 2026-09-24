"""认证服务：轮换、重放、越权、并发、重启持久化。"""
import logging
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.errors import AuthError, FailureReason
from tests.conftest import log_decision, make_service

logger = logging.getLogger("auth-tests")
NOW = 1_000_000


@pytest.fixture()
def alice(service):
    service.register("alice", "pw", ["read"])
    return service


def test_login_issues_token_pair(alice):
    pair = alice.login("alice", "pw", now=NOW)
    log_decision("登录签发", {"sub": "alice"}, "凭据校验通过", f"sid={pair.sid}")
    assert pair.access_token and pair.refresh_token
    assert alice.authorize(pair.access_token, {"read"}, now=NOW).sub == "alice"


def test_login_wrong_password_reason(alice):
    with pytest.raises(AuthError) as exc:
        alice.login("alice", "nope", now=NOW)
    log_decision("错误密码", {"sub": "alice"}, "口令散列不一致", exc.value.reason.value)
    assert exc.value.reason == FailureReason.INVALID_CREDENTIALS


def test_refresh_rotates_and_old_token_replay_revokes_session(alice):
    pair1 = alice.login("alice", "pw", now=NOW)
    pair2 = alice.refresh(pair1.refresh_token, now=NOW + 1)
    log_decision("令牌轮换", {"old": pair1.refresh_token[:8]}, "旧令牌未消费且未过期",
                 f"新令牌签发, 旧令牌失效: {pair1.refresh_token != pair2.refresh_token}")
    assert pair2.refresh_token != pair1.refresh_token
    assert pair2.sid == pair1.sid  # 同一会话内轮换

    with pytest.raises(AuthError) as exc:
        alice.refresh(pair1.refresh_token, now=NOW + 2)
    log_decision("重放旧刷新令牌", {"token": pair1.refresh_token[:8]},
                 "散列存在于已消费历史", exc.value.reason.value)
    assert exc.value.reason == FailureReason.REFRESH_TOKEN_REUSED

    # 会话整体失效：新访问令牌与新刷新令牌都不可用
    with pytest.raises(AuthError) as exc2:
        alice.authenticate(pair2.access_token, now=NOW + 3)
    assert exc2.value.reason == FailureReason.SESSION_REVOKED
    with pytest.raises(AuthError) as exc3:
        alice.refresh(pair2.refresh_token, now=NOW + 3)
    log_decision("重放后会话", {"sid": pair1.sid}, "revoked=True", exc3.value.reason.value)
    assert exc3.value.reason == FailureReason.SESSION_REVOKED


def test_unknown_refresh_token(alice):
    with pytest.raises(AuthError) as exc:
        alice.refresh("does-not-exist", now=NOW)
    log_decision("未知刷新令牌", {"token": "does-not-exist"}, "索引无此散列", exc.value.reason.value)
    assert exc.value.reason == FailureReason.REFRESH_TOKEN_UNKNOWN


def test_scope_default_deny(alice):
    pair = alice.login("alice", "pw", now=NOW)
    with pytest.raises(AuthError) as exc:
        alice.authorize(pair.access_token, {"write"}, now=NOW)
    log_decision("越权访问", {"scopes": ["read"], "required": ["write"]},
                 "所需作用域不是令牌作用域子集(默认拒绝)", exc.value.reason.value)
    assert exc.value.reason == FailureReason.INSUFFICIENT_SCOPE


def test_expired_access_token(alice):
    pair = alice.login("alice", "pw", now=NOW)
    with pytest.raises(AuthError) as exc:
        alice.authenticate(pair.access_token, now=NOW + 3600)
    log_decision("过期访问令牌", {"exp": NOW + 60}, "now >= exp", exc.value.reason.value)
    assert exc.value.reason == FailureReason.TOKEN_EXPIRED


def test_concurrent_refresh_only_one_succeeds(alice):
    pair = alice.login("alice", "pw", now=NOW)
    results, errors = [], []

    def attempt(i):
        try:
            results.append(alice.refresh(pair.refresh_token, now=NOW + 1))
        except AuthError as e:
            errors.append(e.reason)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(attempt, range(8)))
    reused = errors.count(FailureReason.REFRESH_TOKEN_REUSED)
    revoked = errors.count(FailureReason.SESSION_REVOKED)
    log_decision("并发刷新", {"并发数": 8}, "刷新临界区串行化, 检查-消费原子",
                 f"成功={len(results)} 重放={reused} 会话失效={revoked}")
    assert len(results) == 1  # 不得同时成功
    assert reused >= 1  # 至少一个被识别为重放
    assert reused + revoked == 7


def test_login_lockout_and_persistence_across_restart(state_path):
    svc = make_service(state_path)
    svc.register("bob", "pw", [])
    for i in range(3):
        with pytest.raises(AuthError):
            svc.login("bob", "bad", now=NOW + i)
    with pytest.raises(AuthError) as exc:
        svc.login("bob", "pw", now=NOW + 10)  # 正确密码也被拒
    log_decision("失败累积锁定", {"失败次数": 3}, "达到阈值进入锁定期", exc.value.reason.value)
    assert exc.value.reason == FailureReason.RATE_LIMITED

    svc2 = make_service(state_path)  # 模拟进程重启
    with pytest.raises(AuthError) as exc2:
        svc2.login("bob", "pw", now=NOW + 20)
    log_decision("重启后锁定", {"重启": True}, "锁定标记已持久化", exc2.value.reason.value)
    assert exc2.value.reason == FailureReason.RATE_LIMITED


def test_refresh_survives_restart(state_path):
    svc = make_service(state_path)
    svc.register("carol", "pw", ["read"])
    pair = svc.login("carol", "pw", now=NOW)
    svc2 = make_service(state_path)  # 重启
    pair2 = svc2.refresh(pair.refresh_token, now=NOW + 1)
    log_decision("重启后刷新", {"sid": pair.sid}, "会话与刷新索引已持久化", "轮换成功")
    assert pair2.sid == pair.sid
    # 重放在重启后仍可被识别
    with pytest.raises(AuthError) as exc:
        make_service(state_path).refresh(pair.refresh_token, now=NOW + 2)
    assert exc.value.reason == FailureReason.REFRESH_TOKEN_REUSED
