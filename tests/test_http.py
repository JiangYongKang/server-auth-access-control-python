"""HTTP 层：状态码与失败原因映射、未授权不泄露资源存在性。"""
import logging

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import log_decision

logger = logging.getLogger("auth-tests")


@pytest.fixture()
def client(tmp_path):
    app = create_app(tmp_path / "state.json", secret="http-test", access_ttl=60)
    c = TestClient(app)
    c.post("/register", json={"sub": "alice", "password": "pw", "scopes": ["read"]})
    return c


def login(client) -> dict:
    r = client.post("/login", json={"sub": "alice", "password": "pw"})
    assert r.status_code == 200
    return r.json()


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_full_flow_over_http(client):
    pair = login(client)
    r = client.get("/resources/doc-1", headers=auth(pair["access_token"]))
    log_decision("HTTP 授权访问", {"resource": "doc-1", "scope": "read"},
                 "令牌有效且作用域匹配", f"status={r.status_code}")
    assert r.status_code == 200 and r.json()["body"] == "机密内容"

    r2 = client.post("/refresh", json={"refresh_token": pair["refresh_token"]})
    assert r2.status_code == 200
    r3 = client.post("/refresh", json={"refresh_token": pair["refresh_token"]})
    log_decision("HTTP 重放", {"token": "旧刷新令牌"}, "已消费", r3.json()["error"])
    assert r3.status_code == 401 and r3.json()["error"] == "refresh_token_reused"


def test_unauthorized_does_not_leak_resource_existence(client):
    # 存在的资源与不存在的资源，对未授权请求返回完全一致的响应
    for name in ("doc-1", "no-such-doc"):
        r_no_token = client.get(f"/resources/{name}")
        r_bad_token = client.get(f"/resources/{name}", headers=auth("forged.token.here"))
        assert r_no_token.status_code == 401 and r_no_token.json()["error"] == "token_missing"
        assert r_bad_token.status_code == 401 and r_bad_token.json()["error"] == "token_invalid"
    # 越权（缺少 write 作用域）同样无法区分资源是否存在
    pair = login(client)
    responses = [client.post(f"/resources/{n}", headers=auth(pair["access_token"])) for n in ("doc-1", "no-such-doc")]
    bodies = [r.json() for r in responses]
    log_decision("存在性不泄露", {"names": ["doc-1", "no-such-doc"]},
                 "权限判定先于资源查找", f"响应一致={len(set(map(str, bodies))) == 1}")
    assert all(r.status_code == 403 and r.json()["error"] == "insufficient_scope" for r in responses)


def test_distinct_error_reasons_over_http(client):
    pair = login(client)
    cases = {}
    cases["no_token"] = client.get("/resources/doc-1").json()["error"]
    cases["forged"] = client.get("/resources/doc-1", headers=auth("a.b.c")).json()["error"]
    cases["insufficient_scope"] = client.post("/resources/doc-1", headers=auth(pair["access_token"])).json()["error"]
    cases["bad_credentials"] = client.post("/login", json={"sub": "alice", "password": "x"}).json()["error"]
    log_decision("失败原因可区分", {"场景数": len(cases)}, "各场景 error 字段互不相同", str(cases))
    assert len(set(cases.values())) == len(cases)
