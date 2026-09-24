"""可复现性：相同输入 + 注入时钟下，多次运行得到相同的判定序列与错误码。"""
from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from app.auth.errors import ErrorCode
from tests.conftest import T0, make_config, make_service

logger = logging.getLogger("test.determinism")


def _run_scenario(cfg):
    svc = make_service(cfg)
    decisions: list[str] = []

    def expect_auth_error(fn, label):
        try:
            fn()
            decisions.append(f"{label}:ok")
        except Exception as exc:
            decisions.append(f"{label}:{getattr(exc, 'error_code', type(exc).__name__).value if hasattr(getattr(exc, 'error_code', None), 'value') else type(exc).__name__}")

    t = svc.login("alice", "alice-password", now=T0)
    expect_auth_error(lambda: svc.login("alice", "bad", now=T0 + 1), "login-bad")
    t2 = svc.refresh(t.refresh_token, now=T0 + 2); decisions.append("refresh:ok")
    expect_auth_error(lambda: svc.refresh(t.refresh_token, now=T0 + 3), "replay")
    expect_auth_error(lambda: svc.refresh(t2.refresh_token, now=T0 + 4), "revoked")
    expect_auth_error(lambda: svc.authorize(f"Bearer {t.access_token}", "profile:read", now=T0), "allow")
    expect_auth_error(lambda: svc.authorize(f"Bearer {t.access_token}", "admin:action", now=T0), "scope")
    expect_auth_error(lambda: svc.authorize(None, "profile:read", now=T0), "missing")
    expect_auth_error(lambda: svc.authorize("Bearer x.y.z", "profile:read", now=T0), "forgery")
    return decisions


def test_same_inputs_produce_same_decisions(tmp_path: Path):
    results = []
    for i in range(3):
        cfg = make_config(tmp_path / f"run{i}")
        results.append(_run_scenario(cfg))
    logger.info("decision sequence:\n  %s", "\n  ".join(results[0]))
    assert results[0] == results[1] == results[2]
