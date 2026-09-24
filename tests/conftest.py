import logging
import pathlib
import tempfile

import pytest

from app.auth import AuthService
from app.ratelimit import RateLimiter
from app.store import Store

logger = logging.getLogger("auth-tests")


@pytest.fixture()
def state_path(tmp_path: pathlib.Path) -> pathlib.Path:
    return tmp_path / "state.json"


def make_service(path: pathlib.Path, **overrides) -> AuthService:
    """从同一状态文件构建服务（重复调用即模拟进程重启）。"""
    params = dict(secret="test-secret", access_ttl=60, refresh_ttl=3600)
    params.update(overrides)
    store = Store(path)
    limiter = RateLimiter(store, window=60, max_attempts=3, lockout=300)
    return AuthService(store, limiter, **params)


@pytest.fixture()
def service(state_path: pathlib.Path) -> AuthService:
    return make_service(state_path)


def log_decision(case: str, inputs: dict, basis: str, outcome: str) -> None:
    """单测日志：打印输入与判定依据。"""
    logger.info("用例=%s | 输入=%s | 判定依据=%s | 结果=%s", case, inputs, basis, outcome)
