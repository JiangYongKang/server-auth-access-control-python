"""会话管理：列表可见性、三种撤销路径、撤销即时生效、幂等、并发确定性、上限与清理。"""
from __future__ import annotations

import logging
import threading

import pytest

from app.auth.errors import (
    AccessSessionRevokedError,
    RefreshConcurrentError,
    RefreshSessionRevokedError,
    RefreshTokenConsumedError,
    RefreshTokenInvalidError,
    SessionNotFoundError,
)
from app.auth.service import REASON_EVICTED, REASON_LOGOUT
from tests.conftest import T0, make_config, make_service

logger = logging.getLogger("test.sessions")


def _session_ids(service, username):
    return [s.session_id for s in service.store.db.sessions.values()
            if s.username == username]


def _only_session_id(service, username):
    ids = _session_ids(service, username)
    assert len(ids) == 1
    return ids[0]


# ---------------------------------------------------------------------------
# 列表可见性
# ---------------------------------------------------------------------------
def test_login_with_device_id_and_list_own_sessions_only(service):
    a1 = service.login("alice", "alice-password", device_id="alice-phone", now=T0)
    service.login("alice", "alice-password", device_id="alice-laptop", now=T0 + 1)
    service.login("bob", "bob-password", device_id="bob-tablet", now=T0 + 2)
    logger.info("input: alice x2 (phone/laptop), bob x1 (tablet)")

    from app.auth import security
    claims = security.decode_access_token(service.config.secret, a1.access_token, T0)
    mine = service.list_sessions("alice", current_session_id=claims.session_id, now=T0 + 3)

    logger.info("decision: alice sees %d sessions: %s", len(mine),
                [(s["device_id"], s["is_current"]) for s in mine])
    assert len(mine) == 2
    assert {s["device_id"] for s in mine} == {"alice-phone", "alice-laptop"}
    current = [s for s in mine if s["is_current"]]
    assert len(current) == 1 and current[0]["device_id"] == "alice-phone"
    # 每条记录都带建立时间与最近刷新时间字段
    for s in mine:
        assert s["created_at"] > 0
        assert s["last_refresh_at"] is None  # 尚未刷新过
    # bob 的会话绝不出现在 alice 的列表里
    assert all(s["device_id"] != "bob-tablet" for s in mine)


def test_login_without_device_id_still_works(service):
    issued = service.login("alice", "alice-password", now=T0)
    assert issued.access_token
    mine = service.list_sessions("alice", now=T0)
    assert len(mine) == 1 and mine[0]["device_id"] is None
    logger.info("decision: legacy client (no device_id) logs in, device_id=None")


def test_last_refresh_at_updates_on_rotation(service):
    issued = service.login("alice", "alice-password", device_id="dev", now=T0)
    sid = _only_session_id(service, "alice")
    service.refresh(issued.refresh_token, now=T0 + 7)
    mine = service.list_sessions("alice", current_session_id=sid, now=T0 + 8)
    logger.info("decision: last_refresh_at=%s created_at=%s",
                mine[0]["last_refresh_at"], mine[0]["created_at"])
    assert mine[0]["last_refresh_at"] == T0 + 7
    assert mine[0]["created_at"] == T0


# ---------------------------------------------------------------------------
# 三种撤销路径 + 撤销即时生效
# ---------------------------------------------------------------------------
def test_logout_current_session_invalidates_tokens_immediately(service):
    issued = service.login("alice", "alice-password", device_id="phone", now=T0)
    sid = _only_session_id(service, "alice")
    service.logout("alice", sid, now=T0 + 1)
    logger.info("input: logout session=%s; then use its tokens", sid)

    with pytest.raises(AccessSessionRevokedError) as exc:
        service.authorize(f"Bearer {issued.access_token}", "profile:read", now=T0 + 2)
    logger.info("decision: access denied immediately -> %s", exc.value.error_code.value)

    with pytest.raises(RefreshSessionRevokedError) as exc2:
        service.refresh(issued.refresh_token, now=T0 + 3)
    logger.info("decision: refresh denied -> %s", exc2.value.error_code.value)
    assert _session_ids(service, "alice") == [sid]  # 记录仍在（未清理），状态为撤销
    assert service.store.db.sessions[sid].revoke_reason == REASON_LOGOUT


def test_revoke_specific_session_by_id(service):
    i1 = service.login("alice", "alice-password", device_id="dev-1", now=T0)
    i2 = service.login("alice", "alice-password", device_id="dev-2", now=T0 + 1)
    sid1, sid2 = _session_ids(service, "alice")
    logger.info("input: revoke %s, keep %s", sid1, sid2)

    service.revoke_session("alice", sid1, now=T0 + 2)
    with pytest.raises(AccessSessionRevokedError):
        service.authorize(f"Bearer {i1.access_token}", "profile:read", now=T0 + 3)
    with pytest.raises(RefreshSessionRevokedError):
        service.refresh(i1.refresh_token, now=T0 + 3)
    # 不牵连其它会话
    assert service.authorize(f"Bearer {i2.access_token}", "profile:read", now=T0 + 3) == "alice"
    rotated = service.refresh(i2.refresh_token, now=T0 + 4)
    assert rotated.refresh_token
    logger.info("decision: sid1 revoked, sid2 unaffected")


def test_revoke_others_keeps_current(service):
    i1 = service.login("alice", "alice-password", device_id="dev-1", now=T0)
    i2 = service.login("alice", "alice-password", device_id="dev-2", now=T0 + 1)
    i3 = service.login("alice", "alice-password", device_id="dev-3", now=T0 + 2)
    sid3 = _session_ids(service, "alice")[-1]
    logger.info("input: revoke others, keep current=%s", sid3)

    count = service.revoke_other_sessions("alice", sid3, now=T0 + 3)
    assert count == 2
    for issued in (i1, i2):
        with pytest.raises(AccessSessionRevokedError):
            service.authorize(f"Bearer {issued.access_token}", "profile:read", now=T0 + 4)
        with pytest.raises(RefreshSessionRevokedError):
            service.refresh(issued.refresh_token, now=T0 + 4)
    assert service.authorize(f"Bearer {i3.access_token}", "profile:read", now=T0 + 4) == "alice"
    mine = service.list_sessions("alice", current_session_id=sid3, now=T0 + 5)
    assert [s["session_id"] for s in mine] == [sid3]
    logger.info("decision: 2 others revoked, current session intact")


def test_revoke_someone_elses_session_gives_no_feedback(service):
    service.login("alice", "alice-password", now=T0)
    bob_issued = service.login("bob", "bob-password", now=T0 + 1)
    bob_sid = _only_session_id(service, "bob")
    logger.info("input: alice tries to revoke bob's session %s", bob_sid)

    with pytest.raises(SessionNotFoundError) as exc:
        service.revoke_session("alice", bob_sid, now=T0 + 2)
    logger.info("decision: %s (same as nonexistent id)", exc.value.error_code.value)
    # 与“撤销一个不存在的 id”得到完全相同的错误，无法借此探测他人会话
    with pytest.raises(SessionNotFoundError):
        service.revoke_session("alice", "0" * 32, now=T0 + 2)
    # bob 的会话不受影响
    assert service.refresh(bob_issued.refresh_token, now=T0 + 3).refresh_token


def test_revoke_is_idempotent(service):
    service.login("alice", "alice-password", now=T0)
    sid = _only_session_id(service, "alice")
    service.revoke_session("alice", sid, now=T0 + 1)
    reason_after_first = service.store.db.sessions[sid].revoke_reason
    # 重复撤销：结果一致、不抛错、不改变原撤销原因、不会重新激活
    service.revoke_session("alice", sid, now=T0 + 2)
    service.revoke_session("alice", sid, now=T0 + 3)
    session = service.store.db.sessions[sid]
    logger.info("decision: revoked=%s reason=%s (unchanged)", session.revoked,
                session.revoke_reason)
    assert session.revoked is True
    assert session.revoke_reason == reason_after_first


# ---------------------------------------------------------------------------
# 并发：撤销与刷新/访问竞争时结果确定
# ---------------------------------------------------------------------------
def test_revoke_vs_refresh_race_has_deterministic_final_state(tmp_path):
    cfg = make_config(tmp_path, refresh_max_failures=100_000,
                      access_max_failures=100_000,
                      max_active_sessions_per_user=1000)
    service = make_service(cfg)
    rounds = 20
    for i in range(rounds):
        now = T0 + i * 10
        issued = service.login("alice", "alice-password", now=now)
        sid = _session_ids(service, "alice")[-1]
        barrier = threading.Barrier(2)
        outcome: dict[str, object] = {}

        def do_refresh():
            barrier.wait()
            try:
                outcome["refresh"] = service.refresh(issued.refresh_token, now=now + 1)
            except RefreshSessionRevokedError:
                outcome["refresh"] = "revoked"
            except RefreshConcurrentError:
                # 撤销持锁期间撞进来的刷新被拒为并发冲突：未成功，最终状态不变
                outcome["refresh"] = "concurrent"

        def do_revoke():
            barrier.wait()
            service.revoke_session("alice", sid, now=now + 1)
            outcome["revoke"] = "ok"

        threads = [threading.Thread(target=do_refresh), threading.Thread(target=do_revoke)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 不变量 1：撤销一定成功；会话最终处于撤销态
        assert "refresh" in outcome, "refresh thread raised an unexpected error"
        assert outcome["revoke"] == "ok"
        assert service.store.db.sessions[sid].revoked is True
        # 不变量 2：无论竞争结果如何，最新的刷新令牌都必须被拒
        latest_refresh = (
            outcome["refresh"].refresh_token
            if hasattr(outcome["refresh"], "refresh_token")
            else issued.refresh_token
        )
        with pytest.raises(RefreshSessionRevokedError):
            service.refresh(latest_refresh, now=now + 2)
        # 不变量 3：最新的访问令牌立即失效
        latest_access = (
            outcome["refresh"].access_token
            if hasattr(outcome["refresh"], "access_token")
            else issued.access_token
        )
        with pytest.raises(AccessSessionRevokedError):
            service.authorize(f"Bearer {latest_access}", "profile:read", now=now + 2)
        logger.info("round %d: refresh_race=%s -> final state revoked, "
                    "subsequent refresh/access denied", i,
                    "refresh_won" if hasattr(outcome["refresh"], "access_token")
                    else "revoke_won")
    logger.info("decision: %d/%d rounds deterministic", rounds, rounds)


def test_revoke_vs_access_race_has_deterministic_final_state(tmp_path):
    cfg = make_config(tmp_path, access_max_failures=100_000,
                      max_active_sessions_per_user=1000)
    service = make_service(cfg)
    rounds = 20
    for i in range(rounds):
        now = T0 + i * 10
        issued = service.login("alice", "alice-password", now=now)
        sid = _session_ids(service, "alice")[-1]
        barrier = threading.Barrier(2)
        outcome: dict[str, str] = {}

        def do_access():
            barrier.wait()
            try:
                service.authorize(f"Bearer {issued.access_token}", "profile:read", now=now + 1)
                outcome["access"] = "allowed"
            except AccessSessionRevokedError:
                outcome["access"] = "revoked"

        def do_revoke():
            barrier.wait()
            service.revoke_session("alice", sid, now=now + 1)

        threads = [threading.Thread(target=do_access), threading.Thread(target=do_revoke)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 撤销生效后，一切后续访问一律被拒
        with pytest.raises(AccessSessionRevokedError):
            service.authorize(f"Bearer {issued.access_token}", "profile:read", now=now + 2)
        logger.info("round %d: racing access=%s; post-revoke access always denied",
                    i, outcome["access"])
    logger.info("decision: %d/%d rounds deterministic", rounds, rounds)


# ---------------------------------------------------------------------------
# 会话上限
# ---------------------------------------------------------------------------
def test_session_limit_evicts_oldest(tmp_path):
    cfg = make_config(tmp_path, max_active_sessions_per_user=2)
    service = make_service(cfg)
    i1 = service.login("alice", "alice-password", device_id="dev-1", now=T0)
    i2 = service.login("alice", "alice-password", device_id="dev-2", now=T0 + 1)
    i3 = service.login("alice", "alice-password", device_id="dev-3", now=T0 + 2)
    logger.info("input: 3 logins with limit=2")

    mine = service.list_sessions("alice", now=T0 + 3)
    assert [s["device_id"] for s in mine] == ["dev-2", "dev-3"]
    sid1 = _session_ids(service, "alice")[0]
    assert service.store.db.sessions[sid1].revoke_reason == REASON_EVICTED
    # 被逐出会话的令牌立即失效，调用方可见明确失败原因
    with pytest.raises(AccessSessionRevokedError):
        service.authorize(f"Bearer {i1.access_token}", "profile:read", now=T0 + 3)
    with pytest.raises(RefreshSessionRevokedError):
        service.refresh(i1.refresh_token, now=T0 + 3)
    # 留在上限内的会话不受影响
    assert service.authorize(f"Bearer {i2.access_token}", "profile:read", now=T0 + 3) == "alice"
    assert service.refresh(i3.refresh_token, now=T0 + 4).refresh_token
    logger.info("decision: oldest evicted (reason=%s), newest 2 kept", REASON_EVICTED)


# ---------------------------------------------------------------------------
# 清理
# ---------------------------------------------------------------------------
def test_cleanup_removes_dead_keeps_alive(service):
    dead = service.login("alice", "alice-password", device_id="dead", now=T0)
    alive = service.login("alice", "alice-password", device_id="alive", now=T0 + 1)
    rotated = service.refresh(alive.refresh_token, now=T0 + 2)
    dead_sid = _session_ids(service, "alice")[0]
    service.revoke_session("alice", dead_sid, now=T0 + 3)
    logger.info("input: 1 revoked session + 1 active session (rotated once)")

    removed = service.cleanup(now=T0 + 4)
    logger.info("decision: cleanup removed=%s", removed)
    assert removed["sessions"] == 1
    assert _session_ids(service, "alice") == [_session_ids(service, "alice")[0]]
    assert service.store.db.sessions[_session_ids(service, "alice")[0]].device_id == "alive"
    # 被撤销会话的令牌记录已清除：再刷新是“无法识别”，而非重新激活
    with pytest.raises(RefreshTokenInvalidError):
        service.refresh(dead.refresh_token, now=T0 + 5)
    # 活跃会话的刷新链不受影响
    assert service.refresh(rotated.refresh_token, now=T0 + 6).refresh_token


def test_cleanup_keeps_replay_evidence_of_active_session(service):
    issued = service.login("alice", "alice-password", now=T0)
    service.refresh(issued.refresh_token, now=T0 + 1)  # 旧令牌 consumed 但未过期
    removed = service.cleanup(now=T0 + 2)
    assert removed["refresh_tokens"] == 0  # 未过期记录（含重放检测证据）必须保留
    # 重放检测仍然有效
    with pytest.raises(RefreshTokenConsumedError):
        service.refresh(issued.refresh_token, now=T0 + 3)
    logger.info("decision: consumed-but-unexpired record kept; replay still detected")


def test_cleanup_removes_expired_sessions_and_tokens(service):
    cfg_ttl = 1000  # conftest: refresh_token_ttl_seconds=1000
    expired = service.login("alice", "alice-password", device_id="old", now=T0)
    # 第二次登录触发登录时的机会清理：已过期会话当场被清掉
    service.login("alice", "alice-password", device_id="new", now=T0 + cfg_ttl + 1)
    logger.info("input: old session expired at %.0f; new login at %.0f triggers cleanup",
                T0 + cfg_ttl, T0 + cfg_ttl + 1)

    mine = service.list_sessions("alice", now=T0 + cfg_ttl + 2)
    assert [s["device_id"] for s in mine] == ["new"]
    # 过期会话与其令牌记录已不存在：旧刷新令牌无法换发新令牌
    with pytest.raises(RefreshTokenInvalidError):
        service.refresh(expired.refresh_token, now=T0 + cfg_ttl + 2)
    # 显式清理幂等：没有新的可清理对象
    removed = service.cleanup(now=T0 + cfg_ttl + 2)
    logger.info("decision: expired session/token gone; explicit cleanup removed=%s", removed)
    assert removed["sessions"] == 0


# ---------------------------------------------------------------------------
# 重启后状态保持
# ---------------------------------------------------------------------------
def _restart(config):
    from app.auth.rate_limit import RateLimiter
    from app.auth.service import AuthService
    from app.auth.store import JsonStore

    store = JsonStore(config.db_path)
    return AuthService(config, store, RateLimiter(store))


def test_revocation_survives_restart(config, service):
    issued = service.login("alice", "alice-password", device_id="phone", now=T0)
    sid = _only_session_id(service, "alice")
    service.revoke_session("alice", sid, now=T0 + 1)
    logger.info("input: revoked before restart; restarting")

    svc2 = _restart(config)
    with pytest.raises(AccessSessionRevokedError):
        svc2.authorize(f"Bearer {issued.access_token}", "profile:read", now=T0 + 2)
    with pytest.raises(RefreshSessionRevokedError):
        svc2.refresh(issued.refresh_token, now=T0 + 2)
    assert svc2.list_sessions("alice", now=T0 + 2) == []
    logger.info("decision: revocation persists across restart")


def test_session_limit_and_cleanup_survive_restart(tmp_path):
    cfg = make_config(tmp_path, max_active_sessions_per_user=2)
    service = make_service(cfg)
    i1 = service.login("alice", "alice-password", device_id="dev-1", now=T0)
    service.login("alice", "alice-password", device_id="dev-2", now=T0 + 1)
    service.login("alice", "alice-password", device_id="dev-3", now=T0 + 2)
    service.cleanup(now=T0 + 3)  # 清掉被逐出的 dev-1 记录
    logger.info("input: limit=2, 3 logins, cleanup, then restart")

    svc2 = _restart(cfg)
    mine = svc2.list_sessions("alice", now=T0 + 4)
    assert [s["device_id"] for s in mine] == ["dev-2", "dev-3"]
    # 被逐出并清理的会话：刷新令牌记录已不存在，无法换发新令牌
    with pytest.raises(RefreshTokenInvalidError):
        svc2.refresh(i1.refresh_token, now=T0 + 4)
    # 上限在重启后依然生效：再登录一次仍逐出最旧
    service2_login = svc2.login("alice", "alice-password", device_id="dev-4", now=T0 + 5)
    mine = svc2.list_sessions("alice", now=T0 + 6)
    assert [s["device_id"] for s in mine] == ["dev-3", "dev-4"]
    assert service2_login.access_token
    logger.info("decision: limit & cleanup results hold after restart")


# ---------------------------------------------------------------------------
# HTTP 端到端：会话管理端点
# ---------------------------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import main as mainmod
    from app.auth.dependencies import get_service
    from app.auth.rate_limit import RateLimiter
    from app.auth.service import AuthService
    from app.auth.store import JsonStore

    cfg = make_config(tmp_path)
    store = JsonStore(cfg.db_path)
    service = AuthService(cfg, store, RateLimiter(store))
    service.ensure_seed_users()
    fixed = {"now": T0}
    monkeypatch.setattr(service, "now", lambda: fixed["now"])
    mainmod.app.dependency_overrides[get_service] = lambda: service
    c = TestClient(app=mainmod.app)
    yield c
    mainmod.app.dependency_overrides.clear()


def _login(client, username, password, device_id=None):
    payload = {"username": username, "password": password}
    if device_id is not None:
        payload["device_id"] = device_id
    r = client.post("/auth/login", json=payload)
    assert r.status_code == 200
    return r.json()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_sessions_endpoints_over_http(client):
    t1 = _login(client, "alice", "alice-password", device_id="phone")
    t2 = _login(client, "alice", "alice-password", device_id="laptop")
    _login(client, "bob", "bob-password", device_id="bob-dev")
    logger.info("input: alice x2 (phone/laptop), bob x1")

    # 列表：只有自己的会话，且标记当前会话
    r = client.get("/auth/sessions", headers=_auth(t1["access_token"]))
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert {s["device_id"] for s in sessions} == {"phone", "laptop"}
    current = [s for s in sessions if s["is_current"]]
    assert len(current) == 1 and current[0]["device_id"] == "phone"
    sid_phone = current[0]["session_id"]
    sid_laptop = next(s["session_id"] for s in sessions if s["device_id"] == "laptop")
    logger.info("decision: list shows own 2 sessions, current=phone")

    # 老客户端（不带 device_id）登录不受影响
    t3 = _login(client, "alice", "alice-password")
    assert t3["access_token"]

    # 按 id 撤销指定会话：laptop 的访问令牌立即失效
    r = client.delete(f"/auth/sessions/{sid_laptop}", headers=_auth(t1["access_token"]))
    assert r.status_code == 200
    r = client.get("/auth/sessions", headers=_auth(t2["access_token"]))
    assert r.status_code == 401 and r.json()["error"] == "access_session_revoked"
    logger.info("decision: revoke-by-id -> laptop access token invalid immediately")

    # 重复撤销幂等
    r = client.delete(f"/auth/sessions/{sid_laptop}", headers=_auth(t1["access_token"]))
    assert r.status_code == 200

    # 撤销他人/不存在的会话：统一 404，不泄露存在性
    bob_sessions = client.get("/auth/sessions", headers=_auth(
        _login(client, "bob", "bob-password")["access_token"])).json()["sessions"]
    bob_sid = bob_sessions[0]["session_id"]
    r = client.delete(f"/auth/sessions/{bob_sid}", headers=_auth(t1["access_token"]))
    assert r.status_code == 404 and r.json()["error"] == "session_not_found"
    r = client.delete(f"/auth/sessions/{'0' * 32}", headers=_auth(t1["access_token"]))
    assert r.status_code == 404 and r.json()["error"] == "session_not_found"
    logger.info("decision: foreign/nonexistent session both 404 session_not_found")

    # 撤销其它全部会话：当前保留，其余失效
    r = client.post("/auth/sessions/revoke-others", headers=_auth(t1["access_token"]))
    assert r.status_code == 200 and r.json()["revoked_count"] == 1  # t3 被撤销
    r = client.get("/auth/sessions", headers=_auth(t3["access_token"]))
    assert r.status_code == 401 and r.json()["error"] == "access_session_revoked"
    r = client.get("/auth/sessions", headers=_auth(t1["access_token"]))
    assert r.status_code == 200
    assert [s["session_id"] for s in r.json()["sessions"]] == [sid_phone]

    # 登出当前会话：刷新令牌也不能再换发
    r = client.post("/auth/logout", headers=_auth(t1["access_token"]))
    assert r.status_code == 200
    r = client.get("/auth/sessions", headers=_auth(t1["access_token"]))
    assert r.status_code == 401 and r.json()["error"] == "access_session_revoked"
    r = client.post("/auth/refresh", json={"refresh_token": t1["refresh_token"]})
    assert r.status_code == 401 and r.json()["error"] == "refresh_session_revoked"
    logger.info("decision: logout -> access+refresh both invalid immediately")


def test_sessions_endpoints_require_auth(client):
    assert client.get("/auth/sessions").status_code == 401
    assert client.post("/auth/logout").status_code == 401
    assert client.delete(f"/auth/sessions/{'0' * 32}").status_code == 401
    assert client.post("/auth/sessions/revoke-others").status_code == 401
    logger.info("decision: unauthenticated session-management requests all 401")
