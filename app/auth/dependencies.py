"""FastAPI 装配：单例服务与基于作用域的访问控制依赖（默认拒绝）。"""
from __future__ import annotations

from fastapi import Depends, Request

from app.auth.models import AuthConfig
from app.auth.rate_limit import RateLimiter
from app.auth.service import AuthService
from app.auth.store import JsonStore

_config = AuthConfig()
_store = JsonStore(_config.db_path)
_rate_limiter = RateLimiter(_store)
_service = AuthService(_config, _store, _rate_limiter)


def get_config() -> AuthConfig:
    return _config


def get_service() -> AuthService:
    return _service


def require_scope(required_scope: str):
    """生成一个依赖：未显式携带所需作用域一律拒绝（默认拒绝模型）。"""

    def _dep(request: Request, service: AuthService = Depends(get_service)) -> str:
        authorization = request.headers.get("authorization")
        return service.authorize(authorization, required_scope)

    return _dep


def require_auth(request: Request, service: AuthService = Depends(get_service)):
    """依赖：仅要求合法访问令牌（会话管理端点用），返回完整 claims。"""

    return service.authenticate(request.headers.get("authorization"))
