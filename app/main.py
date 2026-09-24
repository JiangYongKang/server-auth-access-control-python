"""FastAPI HTTP 层：认证、刷新与受作用域保护的资源。"""
from __future__ import annotations

import os
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.auth import AuthService, TokenPair
from app.errors import AuthError, FailureReason
from app.ratelimit import RateLimiter
from app.store import Store

_STATUS = {
    FailureReason.INVALID_CREDENTIALS: 401,
    FailureReason.TOKEN_EXPIRED: 401,
    FailureReason.TOKEN_MISSING: 401,
    FailureReason.TOKEN_INVALID: 401,
    FailureReason.TOKEN_TYPE_MISMATCH: 401,
    FailureReason.REFRESH_TOKEN_REUSED: 401,
    FailureReason.REFRESH_TOKEN_UNKNOWN: 401,
    FailureReason.SESSION_REVOKED: 401,
    FailureReason.INSUFFICIENT_SCOPE: 403,
    FailureReason.RATE_LIMITED: 429,
}

# 演示用受保护资源；未授权请求不会泄露其是否存在
_RESOURCES = {"doc-1": {"owner": "alice", "body": "机密内容"}}


class Credentials(BaseModel):
    sub: str
    password: str


class RegisterBody(Credentials):
    scopes: list[str] = []


class RefreshBody(BaseModel):
    refresh_token: str


def _now() -> int:
    return int(time.time())


def _pair_dict(pair: TokenPair) -> dict:
    return {
        "access_token": pair.access_token,
        "refresh_token": pair.refresh_token,
        "sid": pair.sid,
        "scopes": sorted(pair.scopes),
        "token_type": "bearer",
    }


def create_app(
    store_path: str | Path = "auth_state.json",
    *,
    secret: str | None = None,
    access_ttl: int = 900,
    refresh_ttl: int = 7 * 24 * 3600,
    window: int = 60,
    max_attempts: int = 5,
    lockout: int = 300,
) -> FastAPI:
    store = Store(Path(store_path))
    limiter = RateLimiter(store, window=window, max_attempts=max_attempts, lockout=lockout)
    service = AuthService(
        store, limiter,
        secret=secret or os.environ.get("AUTH_SECRET", "dev-only-secret"),
        access_ttl=access_ttl, refresh_ttl=refresh_ttl,
    )

    app = FastAPI(title="auth-access-control")
    app.state.service = service

    @app.exception_handler(AuthError)
    async def auth_error_handler(_: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=_STATUS[exc.reason],
            content={"error": exc.reason.value, "detail": exc.detail},
        )

    def bearer_token(request: Request) -> str:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise AuthError(FailureReason.TOKEN_MISSING, "缺少或格式错误的 Bearer 令牌")
        return header[len("Bearer "):].strip()

    @app.post("/register", status_code=201)
    def register(body: RegisterBody) -> dict:
        service.register(body.sub, body.password, body.scopes)
        return {"sub": body.sub, "scopes": sorted(set(body.scopes))}

    @app.post("/login")
    def login(body: Credentials) -> dict:
        return _pair_dict(service.login(body.sub, body.password, _now()))

    @app.post("/refresh")
    def refresh(body: RefreshBody) -> dict:
        return _pair_dict(service.refresh(body.refresh_token, _now()))

    @app.get("/resources/{name}")
    def get_resource(name: str, token: str = Depends(bearer_token)) -> dict:
        # 先做权限判定再查资源：未授权请求无法区分资源是否存在
        service.authorize(token, {"read"}, _now())
        resource = _RESOURCES.get(name)
        if resource is None:
            return JSONResponse(status_code=404, content={"error": "not_found"})  # type: ignore[return-value]
        return {"name": name, "body": resource["body"]}

    @app.post("/resources/{name}")
    def write_resource(name: str, token: str = Depends(bearer_token)) -> dict:
        service.authorize(token, {"write"}, _now())
        return {"name": name, "updated": True}

    return app


app = create_app()
