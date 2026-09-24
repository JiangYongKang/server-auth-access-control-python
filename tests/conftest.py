"""测试夹具：临时数据库 + 可注入固定时间，保证重复运行结果确定。"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from app.auth.models import AuthConfig
from app.auth.rate_limit import RateLimiter
from app.auth.service import AuthService
from app.auth.store import JsonStore

# 固定基准时间，避免依赖墙钟，保证可复现
T0 = 1_700_000_000.0


def make_config(tmp_path: Path, **overrides) -> AuthConfig:
    cfg = AuthConfig(
        db_path=str(tmp_path / "auth_store.json"),
        access_token_ttl_seconds=100,
        refresh_token_ttl_seconds=1000,
        login_max_failures=3,
        login_lock_seconds=900,
        refresh_max_failures=3,
        refresh_lock_seconds=900,
        access_max_failures=4,
        access_lock_seconds=300,
        failure_window_seconds=600,
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


def make_service(cfg: AuthConfig) -> AuthService:
    store = JsonStore(cfg.db_path)
    service = AuthService(cfg, store, RateLimiter(store))
    service.ensure_seed_users()
    return service


@pytest.fixture
def config(tmp_path):
    return make_config(tmp_path)


@pytest.fixture
def service(config):
    return make_service(config)


@pytest.fixture
def tokens(service):
    return service.login("alice", "alice-password", now=T0)
