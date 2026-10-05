"""HTTP 端到端：状态码、资源隐藏、错误码可区分、限流响应。"""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

import main as mainmod
from app.auth.dependencies import get_service
from app.auth.rate_limit import RateLimiter
from app.auth.service import AuthService
from app.auth.store import JsonStore
from tests.conftest import T0, make_config

logger = logging.getLogger("test.http")


@pytest.fixture
def client_config(tmp_path):
    return make_config(tmp_path)


@pytest.fixture
def client(client_config, monkeypatch):
    # 固定时间：让 HTTP 层调用也使用注入时钟
    store = JsonStore(client_config.db_path)
    service = AuthService(client_config, store, RateLimiter(store))
    service.ensure_seed_users()

    fixed = {"now": T0}

    def fake_now():
        return fixed["now"]

    monkeypatch.setattr(service, "now", fake_now)
    mainmod.app.dependency_overrides[get_service] = lambda: service

    c = TestClient(app=mainmod.app)
    c._fixed = fixed  # type: ignore[attr-defined]
    yield c
    mainmod.app.dependency_overrides.clear()


def login(client, username, password):
    return client.post("/auth/login", json={"username": username, "password": password})


def test_login_success_and_protected_access(client):
    r = login(client, "alice", "alice-password")
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "Bearer"
    at = body["access_token"]
    r = client.get("/protected/profile", headers={"Authorization": f"Bearer {at}"})
    assert r.status_code == 200
    logger.info("decision: 200 with valid token")


def test_protected_endpoint_hides_existence_on_failure(client):
    # 无令牌、坏令牌、越权 -> 全部 404，与不存在路径外形一致
    assert client.get("/protected/profile").status_code == 404
    assert client.get("/protected/profile",
                      headers={"Authorization": "Bearer x.y.z"}).status_code == 404
    assert client.get("/protected/does-not-exist").status_code == 404

    r = login(client, "alice", "alice-password")
    at = r.json()["access_token"]
    r = client.post("/protected/admin/action", headers={"Authorization": f"Bearer {at}"})
    assert r.status_code == 404
    # 虽然是 404，错误原因仍可程序化区分
    assert r.json()["error"] == "access_scope_insufficient"
    logger.info("decision: protected failures all 404, codes still distinct")


@pytest.mark.parametrize("header,expected_code", [
    (None, "access_token_missing"),
    ("Bearer x.y.z", "access_token_forgery"),
    ("Bearer garbage.token", "access_token_malformed"),
])
def test_protected_error_codes_are_distinct(client, header, expected_code):
    kwargs = {"headers": {"Authorization": header}} if header else {}
    r = client.get("/protected/profile", **kwargs)
    assert r.status_code == 404
    assert r.json()["error"] == expected_code


def test_login_failure_and_rate_limit_codes(client):
    r = login(client, "alice", "wrong")
    assert r.status_code == 401 and r.json()["error"] == "invalid_credentials"
    r = login(client, "alice", "wrong")
    assert r.status_code == 401 and r.json()["error"] == "invalid_credentials"
    r = login(client, "alice", "wrong")  # 第三次 -> 锁定
    assert r.status_code == 429 and r.json()["error"] == "rate_limited_login"
    # 锁定期正确密码也明确拒绝
    r = login(client, "alice", "alice-password")
    assert r.status_code == 429 and r.json()["error"] == "rate_limited_login"
    logger.info("decision: login lockout enforced with 429")


def test_refresh_rotation_replay_and_revocation_over_http(client):
    rt = login(client, "alice", "alice-password").json()["refresh_token"]
    r = client.post("/auth/refresh", json={"refresh_token": rt})
    assert r.status_code == 200
    rt2 = r.json()["refresh_token"]

    r = client.post("/auth/refresh", json={"refresh_token": rt})
    assert r.status_code == 401 and r.json()["error"] == "refresh_token_consumed"

    r = client.post("/auth/refresh", json={"refresh_token": rt2})
    assert r.status_code == 401 and r.json()["error"] == "refresh_family_revoked"
    logger.info("decision: rotation/replay/revocation codes over HTTP verified")


def test_concurrent_refresh_over_http(client):
    import concurrent.futures

    rt = login(client, "alice", "alice-password").json()["refresh_token"]
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        futs = [pool.submit(client.post, "/auth/refresh",
                            json={"refresh_token": rt}) for _ in range(2)]
        results = [f.result() for f in futs]
    statuses = sorted(r.status_code for r in results)
    codes = sorted(r.json().get("error", "ok") for r in results)
    logger.info("decision: concurrent HTTP refresh statuses=%s codes=%s", statuses, codes)
    assert statuses == [200, 429]
    assert codes == ["ok", "refresh_concurrent"]


# ----------------------------------------------------------------------
# 会话管理端点
# ----------------------------------------------------------------------
def test_login_with_client_id_and_list_sessions(client):
    r = client.post("/auth/login", json={
        "username": "alice", "password": "alice-password", "client_id": "alice-laptop",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["session_id"]
    logger.info("input: login with client_id; decision: session_id=%s", body["session_id"])

    r = client.get("/auth/sessions",
                   headers={"Authorization": f"Bearer {body['access_token']}"})
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    logger.info("decision: sessions=%s", sessions)
    assert len(sessions) == 1
    assert sessions[0]["client_id"] == "alice-laptop"
    assert sessions[0]["is_current"] is True
    assert sessions[0]["created_at"] > 0


def test_login_without_client_id_still_works(client):
    r = login(client, "alice", "alice-password")
    assert r.status_code == 200
    body = r.json()
    r = client.get("/auth/sessions",
                   headers={"Authorization": f"Bearer {body['access_token']}"})
    assert r.json()["sessions"][0]["client_id"] is None
    logger.info("decision: legacy login (no client_id) unaffected")


def test_sessions_endpoint_requires_auth(client):
    r = client.get("/auth/sessions")
    assert r.status_code == 401
    assert r.json()["error"] == "access_token_missing"
    logger.info("decision: unauthenticated session list -> 401")


def test_logout_invalidates_tokens_immediately_over_http(client):
    body = login(client, "alice", "alice-password").json()
    at = body["access_token"]

    r = client.post("/auth/logout", headers={"Authorization": f"Bearer {at}"})
    assert r.status_code == 200 and r.json()["revoked"] is True

    r = client.get("/protected/profile", headers={"Authorization": f"Bearer {at}"})
    assert r.status_code == 404  # 受保护资源失败仍不泄露存在性
    assert r.json()["error"] == "session_revoked"
    logger.info("decision: access after logout -> 404 session_revoked (immediate)")

    r = client.post("/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert r.status_code == 401
    assert r.json()["error"] == "refresh_family_revoked"
    logger.info("decision: refresh after logout -> 401 refresh_family_revoked")


def test_revoke_by_id_and_revoke_others_over_http(client):
    s1 = login(client, "alice", "alice-password").json()
    s2 = client.post("/auth/login", json={
        "username": "alice", "password": "alice-password", "client_id": "second",
    }).json()
    s3 = client.post("/auth/login", json={
        "username": "alice", "password": "alice-password", "client_id": "third",
    }).json()

    # 按 id 撤销 s1（用 s3 的令牌操作）
    r = client.post("/auth/sessions/revoke",
                    json={"session_id": s1["session_id"]},
                    headers={"Authorization": f"Bearer {s3['access_token']}"})
    assert r.status_code == 200 and r.json()["revoked"] is True
    r = client.get("/protected/profile",
                   headers={"Authorization": f"Bearer {s1['access_token']}"})
    assert r.status_code == 404 and r.json()["error"] == "session_revoked"

    # 撤销他人会话：响应一致，不做任何变更（不泄露存在性）
    bob = login(client, "bob", "bob-password").json()
    r = client.post("/auth/sessions/revoke",
                    json={"session_id": bob["session_id"]},
                    headers={"Authorization": f"Bearer {s3['access_token']}"})
    assert r.status_code == 200 and r.json()["revoked"] is True
    r = client.get("/auth/sessions",
                   headers={"Authorization": f"Bearer {bob['access_token']}"})
    assert len(r.json()["sessions"]) == 1  # bob 会话完好

    # 撤销除当前外全部：s2 失效，s3 存活
    r = client.post("/auth/sessions/revoke-others",
                    headers={"Authorization": f"Bearer {s3['access_token']}"})
    assert r.status_code == 200
    assert r.json()["revoked_sessions"] == [s2["session_id"]]
    r = client.get("/protected/profile",
                   headers={"Authorization": f"Bearer {s2['access_token']}"})
    assert r.status_code == 404 and r.json()["error"] == "session_revoked"
    r = client.get("/auth/sessions",
                   headers={"Authorization": f"Bearer {s3['access_token']}"})
    assert [s["session_id"] for s in r.json()["sessions"]] == [s3["session_id"]]
    logger.info("decision: revoke-by-id / foreign-noop / revoke-others all correct over HTTP")
