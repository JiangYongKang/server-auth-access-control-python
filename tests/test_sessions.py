"""会话管理：列表可见性、三种撤销路径、撤销即时生效、幂等、并发确定性、上限与清理。"""
from __future__ import annotations

import logging
import threading

import pytest

from app.auth.errors import (
    AccessTokenExpiredError,
    RefreshFamilyRevokedError,
    RefreshTokenConsumedError,
    SessionRevokedError,
)
from tests.conftest import T0, make_config, make_service

logger = logging.getLogger("test.sessions")


def _hdr(token: str) -> str:
    return f"Bearer {token}"


def _reset_failure_counters(service, username: str = "alice") -> None:
    """并发用例每轮都会制造“确定性拒绝”，避免跨轮累积触发既有频次锁定，
    使本用例专注于撤销/并发语义而非限流。"""
    from app.auth.rate_limit import RateLimiter

    with service.store:
        service.rate_limiter.reset(RateLimiter.access_key(username))
        service.rate_limiter.reset(RateLimiter.refresh_key(username))


# ----------------------------------------------------------------------
# 会话可见性
# ----------------------------------------------------------------------
def test_login_with_and_without_client_label(service):
    with_label = service.login("alice", "alice-password", client_label="alice-laptop", now=T0)
    without_label = service.login("alice", "alice-password", now=T0 + 1)  # 老客户端不携带
    logger.info("input: login with client_label=%r and without; both must succeed",
                "alice-laptop")

    infos = service.list_sessions(_hdr(without_label.access_token), now=T0 + 2)
    by_id = {i.session_id: i for i in infos}
    logger.info("decision: sessions=%s", [(i.client_label, i.is_current) for i in infos])
    assert by_id[with_label.session_id].client_label == "alice-laptop"
    assert by_id[without_label.session_id].client_label is None
    assert by_id[without_label.session_id].is_current is True
    assert by_id[with_label.session_id].is_current is False


def test_list_sessions_returns_only_own(service):
    alice1 = service.login("alice", "alice-password", client_label="a1", now=T0)
    alice2 = service.login("alice", "alice-password", client_label="a2", now=T0 + 1)
    bob = service.login("bob", "bob-password", client_label="b1", now=T0 + 2)
    logger.info("input: alice x2 sessions, bob x1; alice lists her sessions")

    infos = service.list_sessions(_hdr(alice1.access_token), now=T0 + 3)
    ids = {i.session_id for i in infos}
    logger.info("decision: alice sees=%s; bob session hidden=%s",
                sorted(ids), bob.session_id not in ids)
    assert ids == {alice1.session_id, alice2.session_id}
    assert bob.session_id not in ids
    # 每条都带设备标识 / 建立时间 / 最近刷新时间 / 是否当前会话
    current = [i for i in infos if i.is_current]
    assert len(current) == 1 and current[0].session_id == alice1.session_id
    assert all(i.created_at > 0 for i in infos)
    assert all(i.last_refresh_at == 0.0 for i in infos)


def test_list_sessions_reflects_last_refresh(service, tokens):
    rotated = service.refresh(tokens.refresh_token, now=T0 + 10)
    infos = service.list_sessions(_hdr(rotated.access_token), now=T0 + 11)
    logger.info("input: refresh at T0+10; decision: last_refresh_at=%.1f",
                infos[0].last_refresh_at)
    assert infos[0].last_refresh_at == T0 + 10


# ----------------------------------------------------------------------
# 三种撤销路径 + 撤销即时生效
# ----------------------------------------------------------------------
def test_logout_current_session_invalidates_tokens_immediately(service):
    stay = service.login("alice", "alice-password", client_label="stay", now=T0)
    leave = service.login("alice", "alice-password", client_label="leave", now=T0 + 1)
    logger.info("input: logout session=%s (access token still within ttl)", leave.session_id)

    service.logout(_hdr(leave.access_token), now=T0 + 2)

    # 访问令牌未自然过期，但必须立即失效
    with pytest.raises(SessionRevokedError) as exc:
        service.authorize(_hdr(leave.access_token), "profile:read", now=T0 + 3)
    logger.info("decision: access after logout -> %s (token not yet expired)",
                exc.value.error_code.value)
    # 刷新令牌也不能再换出新令牌
    with pytest.raises(RefreshFamilyRevokedError):
        service.refresh(leave.refresh_token, now=T0 + 3)
    logger.info("decision: refresh after logout -> refresh_family_revoked")
    # 其它会话不受牵连
    assert service.authorize(_hdr(stay.access_token), "profile:read", now=T0 + 3) == "alice"
    infos = service.list_sessions(_hdr(stay.access_token), now=T0 + 3)
    assert [i.session_id for i in infos] == [stay.session_id]


def test_revoke_session_by_id(service):
    s1 = service.login("alice", "alice-password", client_label="s1", now=T0)
    s2 = service.login("alice", "alice-password", client_label="s2", now=T0 + 1)
    logger.info("input: revoke session=%s via session=%s", s1.session_id, s2.session_id)

    acted = service.revoke_session(_hdr(s2.access_token), s1.session_id, now=T0 + 2)
    assert acted is True

    with pytest.raises(SessionRevokedError):
        service.authorize(_hdr(s1.access_token), "profile:read", now=T0 + 3)
    with pytest.raises(RefreshFamilyRevokedError):
        service.refresh(s1.refresh_token, now=T0 + 3)
    assert service.authorize(_hdr(s2.access_token), "profile:read", now=T0 + 3) == "alice"
    logger.info("decision: target revoked immediately; other session intact")


def test_revoke_other_sessions(service):
    s1 = service.login("alice", "alice-password", client_label="s1", now=T0)
    s2 = service.login("alice", "alice-password", client_label="s2", now=T0 + 1)
    s3 = service.login("alice", "alice-password", client_label="s3", now=T0 + 2)
    logger.info("input: revoke-others from session=%s; expect %s and %s revoked",
                s3.session_id, s1.session_id, s2.session_id)

    revoked = service.revoke_other_sessions(_hdr(s3.access_token), now=T0 + 3)
    logger.info("decision: revoked=%s", revoked)
    assert sorted(revoked) == sorted([s1.session_id, s2.session_id])

    for s in (s1, s2):
        with pytest.raises(SessionRevokedError):
            service.authorize(_hdr(s.access_token), "profile:read", now=T0 + 4)
        with pytest.raises(RefreshFamilyRevokedError):
            service.refresh(s.refresh_token, now=T0 + 4)
    # 当前会话仍然可用
    assert service.authorize(_hdr(s3.access_token), "profile:read", now=T0 + 4) == "alice"
    rotated = service.refresh(s3.refresh_token, now=T0 + 4)
    assert rotated.session_id == s3.session_id
    logger.info("decision: current session survives revoke-others")


# ----------------------------------------------------------------------
# 幂等与越权不可见
# ----------------------------------------------------------------------
def test_revoke_is_idempotent_and_not_reactivatable(service):
    s1 = service.login("alice", "alice-password", now=T0)
    s2 = service.login("alice", "alice-password", now=T0 + 1)
    logger.info("input: revoke session=%s twice; then try to use it again", s1.session_id)

    first = service.revoke_session(_hdr(s2.access_token), s1.session_id, now=T0 + 2)
    second = service.revoke_session(_hdr(s2.access_token), s1.session_id, now=T0 + 3)
    logger.info("decision: first acted=%s second acted=%s (repeat is a no-op)", first, second)
    assert first is True and second is False

    with pytest.raises(SessionRevokedError):
        service.authorize(_hdr(s1.access_token), "profile:read", now=T0 + 4)
    with pytest.raises(RefreshFamilyRevokedError):
        service.refresh(s1.refresh_token, now=T0 + 4)
    # 重复撤销不牵连其它会话
    assert service.authorize(_hdr(s2.access_token), "profile:read", now=T0 + 4) == "alice"
    # 已撤销会话不能被重新激活：再次撤销/刷新都不会让它复活
    service.revoke_session(_hdr(s2.access_token), s1.session_id, now=T0 + 5)
    with pytest.raises(RefreshFamilyRevokedError):
        service.refresh(s1.refresh_token, now=T0 + 6)
    logger.info("decision: revoked session stays revoked; siblings unaffected")


def test_revoke_foreign_session_is_invisible_and_noop(service):
    alice = service.login("alice", "alice-password", now=T0)
    bob = service.login("bob", "bob-password", now=T0 + 1)
    logger.info("input: alice tries to revoke bob's session id=%s", bob.session_id)

    acted = service.revoke_session(_hdr(alice.access_token), bob.session_id, now=T0 + 2)
    # 对外表现与成功一致（无异常），但实际不做任何变更
    assert acted is False
    # bob 的会话不受任何影响：仍可刷新、仍可看到自己的会话
    rotated = service.refresh(bob.refresh_token, now=T0 + 3)
    assert rotated.session_id == bob.session_id
    infos = service.list_sessions(_hdr(rotated.access_token), now=T0 + 4)
    assert [i.session_id for i in infos] == [bob.session_id]
    logger.info("decision: foreign revoke is a silent no-op; bob session intact")


def test_revoke_missing_session_is_invisible_noop(service):
    alice = service.login("alice", "alice-password", now=T0)
    acted = service.revoke_session(_hdr(alice.access_token), "no-such-session", now=T0 + 1)
    logger.info("input: revoke non-existent id; decision: acted=%s (same outward result)",
                acted)
    assert acted is False


# ----------------------------------------------------------------------
# 撤销与并发刷新/访问的确定性
# ----------------------------------------------------------------------
def test_revoke_vs_refresh_concurrent_deterministic(service):
    rounds = 12
    for rnd in range(rounds):
        _reset_failure_counters(service)
        tokens = service.login("alice", "alice-password", now=T0)
        barrier = threading.Barrier(2)
        outcome: dict[str, object] = {}

        def do_refresh(tokens=tokens, barrier=barrier, outcome=outcome):
            barrier.wait()
            try:
                outcome["refresh"] = ("ok", service.refresh(tokens.refresh_token, now=T0 + 1))
            except RefreshFamilyRevokedError:
                outcome["refresh"] = ("family_revoked", None)

        def do_revoke(tokens=tokens, barrier=barrier, outcome=outcome):
            barrier.wait()
            service.logout(_hdr(tokens.access_token), now=T0 + 1)
            outcome["revoked"] = True

        t1 = threading.Thread(target=do_refresh)
        t2 = threading.Thread(target=do_revoke)
        t1.start(); t2.start(); t1.join(); t2.join()

        status, rotated = outcome["refresh"]
        logger.info("round=%d input: concurrent logout+refresh; decision: refresh=%s",
                    rnd, status)
        # 两种串行化结果都合法，但最终状态必须确定：会话已撤销
        with pytest.raises(SessionRevokedError):
            service.authorize(_hdr(tokens.access_token), "profile:read", now=T0 + 2)
        if status == "ok":
            # 刷新先完成、撤销随后生效：新令牌对同样必须立即死亡，
            # 绝不允许“撤销生效后又刷出一对可用的新令牌”
            with pytest.raises(RefreshFamilyRevokedError):
                service.refresh(rotated.refresh_token, now=T0 + 2)
            with pytest.raises(SessionRevokedError):
                service.authorize(_hdr(rotated.access_token), "profile:read", now=T0 + 2)
        else:
            with pytest.raises(RefreshFamilyRevokedError):
                service.refresh(tokens.refresh_token, now=T0 + 2)
    logger.info("decision: %d rounds all converged to revoked-and-stays-revoked", rounds)


def test_revoke_vs_access_concurrent_deterministic(service):
    rounds = 12
    for rnd in range(rounds):
        _reset_failure_counters(service)
        tokens = service.login("alice", "alice-password", now=T0)
        barrier = threading.Barrier(5)
        access_outcomes: list[str] = []
        lock = threading.Lock()

        def do_access(tokens=tokens, barrier=barrier,
                      access_outcomes=access_outcomes, lock=lock):
            barrier.wait()
            try:
                service.authorize(_hdr(tokens.access_token), "profile:read", now=T0 + 1)
                with lock:
                    access_outcomes.append("allow")
            except SessionRevokedError:
                with lock:
                    access_outcomes.append("session_revoked")

        def do_revoke(tokens=tokens, barrier=barrier):
            barrier.wait()
            service.logout(_hdr(tokens.access_token), now=T0 + 1)

        threads = [threading.Thread(target=do_access) for _ in range(4)]
        threads.append(threading.Thread(target=do_revoke))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        logger.info("round=%d input: 4 concurrent access + 1 logout; outcomes=%s",
                    rnd, sorted(access_outcomes))
        # 撤销完成后结果确定：之后的一切访问/刷新一律被拒
        with pytest.raises(SessionRevokedError):
            service.authorize(_hdr(tokens.access_token), "profile:read", now=T0 + 2)
        with pytest.raises(RefreshFamilyRevokedError):
            service.refresh(tokens.refresh_token, now=T0 + 2)
    logger.info("decision: %d rounds all converged; post-revoke deny is deterministic", rounds)


def test_concurrent_same_refresh_token_repeated_rounds(service):
    """既有并发刷新场景回归：同一刷新令牌并发使用，重复多轮结果稳定。"""
    from app.auth.errors import RefreshConcurrentError

    rounds = 10
    for rnd in range(rounds):
        tokens = service.login("alice", "alice-password", now=T0)
        barrier = threading.Barrier(4)
        outcomes: list[str] = []
        lock = threading.Lock()

        def worker(tokens=tokens, barrier=barrier, outcomes=outcomes, lock=lock):
            barrier.wait()
            try:
                service.refresh(tokens.refresh_token, now=T0 + 1)
                with lock:
                    outcomes.append("ok")
            except RefreshConcurrentError:
                with lock:
                    outcomes.append("concurrent")

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        logger.info("round=%d input: 4 concurrent refreshes of one token; outcomes=%s",
                    rnd, sorted(outcomes))
        assert sorted(outcomes) == ["concurrent", "concurrent", "concurrent", "ok"]
    logger.info("decision: %d rounds identical -> exactly one winner each time", rounds)


# ----------------------------------------------------------------------
# 会话数量上限
# ----------------------------------------------------------------------
def test_session_cap_evicts_oldest_and_is_visible(tmp_path):
    cfg = make_config(tmp_path, max_active_sessions_per_user=2)
    service = make_service(cfg)
    s1 = service.login("alice", "alice-password", client_label="oldest", now=T0)
    s2 = service.login("alice", "alice-password", client_label="middle", now=T0 + 1)
    logger.info("input: cap=2, third login at T0+2")

    s3 = service.login("alice", "alice-password", client_label="newest", now=T0 + 2)
    logger.info("decision: evicted=%s (deterministic: oldest first)", s3.evicted_sessions)
    assert s3.evicted_sessions == [s1.session_id]

    # 被驱逐会话立即失效；其余存活
    with pytest.raises(SessionRevokedError):
        service.authorize(_hdr(s1.access_token), "profile:read", now=T0 + 3)
    with pytest.raises(RefreshFamilyRevokedError):
        service.refresh(s1.refresh_token, now=T0 + 3)
    assert service.authorize(_hdr(s2.access_token), "profile:read", now=T0 + 3) == "alice"
    infos = service.list_sessions(_hdr(s3.access_token), now=T0 + 3)
    assert {i.session_id for i in infos} == {s2.session_id, s3.session_id}

    # 重启后上限与驱逐结果保持一致
    service2 = make_service(cfg)
    with pytest.raises(SessionRevokedError):
        service2.authorize(_hdr(s1.access_token), "profile:read", now=T0 + 4)
    s4 = service2.login("alice", "alice-password", now=T0 + 4)
    logger.info("decision after restart: next login evicts=%s", s4.evicted_sessions)
    assert s4.evicted_sessions == [s2.session_id]


def test_session_cap_counts_only_alive_sessions(tmp_path):
    cfg = make_config(tmp_path, max_active_sessions_per_user=2)
    service = make_service(cfg)
    s1 = service.login("alice", "alice-password", now=T0)
    service.logout(_hdr(s1.access_token), now=T0 + 1)
    service.login("alice", "alice-password", now=T0 + 2)
    s3 = service.login("alice", "alice-password", now=T0 + 3)
    logger.info("input: logout one of two, then two more logins with cap=2")
    logger.info("decision: evicted=%s (revoked sessions do not count toward cap)",
                s3.evicted_sessions)
    assert s3.evicted_sessions == []


# ----------------------------------------------------------------------
# 清理与重启
# ----------------------------------------------------------------------
def test_cleanup_removes_dead_and_keeps_alive(tmp_path):
    cfg = make_config(tmp_path)
    service = make_service(cfg)
    alive = service.login("alice", "alice-password", client_label="alive", now=T0 + 1400)
    revoked = service.login("alice", "alice-password", client_label="revoked", now=T0 + 1401)
    expired = service.login("bob", "bob-password", client_label="expired", now=T0)
    service.logout(_hdr(revoked.access_token), now=T0 + 1402)
    logger.info("input: cleanup at T0+1500; alive(exp=%.0f) revoked expired(exp=%.0f)",
                T0 + 1400 + cfg.refresh_token_ttl_seconds, T0 + cfg.refresh_token_ttl_seconds)

    stats = service.cleanup(now=T0 + 1500)
    logger.info("decision: cleanup stats=%s", stats)
    assert stats["sessions_removed"] == 2  # revoked + expired
    assert stats["refresh_tokens_removed"] == 1  # expired 会话的刷新记录

    # 存活会话不被误伤：刷新（访问令牌 ttl=100 已自然过期，属预期）、列表全部正常
    rotated = service.refresh(alive.refresh_token, now=T0 + 1501)
    assert rotated.session_id == alive.session_id
    assert service.authorize(_hdr(rotated.access_token), "profile:read", now=T0 + 1501) == "alice"
    infos = service.list_sessions(_hdr(rotated.access_token), now=T0 + 1502)
    assert [i.session_id for i in infos] == [alive.session_id]

    # 被清理的会话仍然被确定性地拒绝（不会复活）：
    # 撤销生效 -> session_revoked；其访问令牌此时也已自然过期 -> expired，两者都是确定拒绝
    with pytest.raises((SessionRevokedError, AccessTokenExpiredError)) as exc:
        service.authorize(_hdr(revoked.access_token), "profile:read", now=T0 + 1502)
    logger.info("decision: cleaned revoked session access -> %s", exc.value.error_code.value)
    with pytest.raises(RefreshFamilyRevokedError):
        service.refresh(revoked.refresh_token, now=T0 + 1502)
    with pytest.raises(Exception) as exc:
        service.refresh(expired.refresh_token, now=T0 + 1502)
    logger.info("decision: cleaned expired token -> %s", type(exc.value).__name__)


def test_cleanup_keeps_consumed_records_for_replay_detection(tmp_path):
    cfg = make_config(tmp_path)
    service = make_service(cfg)
    tokens = service.login("alice", "alice-password", now=T0)
    service.refresh(tokens.refresh_token, now=T0 + 1)
    stats = service.cleanup(now=T0 + 2)
    logger.info("input: cleanup right after rotation; decision: stats=%s "
                "(unexpired consumed record must stay)", stats)
    assert stats["refresh_tokens_removed"] == 0
    # 重放检测仍然有效：旧令牌重放 -> consumed + 整族吊销
    with pytest.raises(RefreshTokenConsumedError):
        service.refresh(tokens.refresh_token, now=T0 + 3)
    logger.info("decision: replay after cleanup still detected -> family revoked")


def test_revocation_and_cap_survive_cleanup_and_restart(tmp_path):
    cfg = make_config(tmp_path, max_active_sessions_per_user=2)
    service = make_service(cfg)
    s1 = service.login("alice", "alice-password", now=T0)
    s2 = service.login("alice", "alice-password", now=T0 + 1)
    service.logout(_hdr(s1.access_token), now=T0 + 2)
    service.cleanup(now=T0 + 3)

    # 重启（同一 db_path 重新装配）
    service2 = make_service(cfg)
    with pytest.raises(SessionRevokedError):
        service2.authorize(_hdr(s1.access_token), "profile:read", now=T0 + 4)
    with pytest.raises(RefreshFamilyRevokedError):
        service2.refresh(s1.refresh_token, now=T0 + 4)
    assert service2.authorize(_hdr(s2.access_token), "profile:read", now=T0 + 4) == "alice"
    # 上限在重启后仍然按存活会话计数（s1 已撤销不占名额）
    s3 = service2.login("alice", "alice-password", now=T0 + 5)
    s4 = service2.login("alice", "alice-password", now=T0 + 6)
    logger.info("decision after cleanup+restart: evicted=%s", s4.evicted_sessions)
    assert s3.evicted_sessions == []
    assert s4.evicted_sessions == [s2.session_id]
