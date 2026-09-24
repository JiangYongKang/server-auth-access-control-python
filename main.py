"""HTTP 装配层。

响应策略（不泄露受保护资源是否存在）：
- /auth/login、/auth/refresh 的认证失败 -> 401/429，携带可区分错误码；
- 任何 /protected/** 资源的认证/授权失败 -> 统一 404，
  响应体仍包含可区分的 error code，供调用方程序化区分原因，
  但对外表现上“资源不存在”，未授权请求无法借此探测资源。
"""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.auth.dependencies import get_service, require_scope
from app.auth.errors import (
    AuthError,
    ErrorCode,
    LoginRateLimitedError,
    RefreshConcurrentError,
    RefreshRateLimitedError,
    AccessRateLimitedError,
)
from app.auth.service import AuthService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = FastAPI(title="server-auth-access-control")

_RATE_LIMITED_CODES = {
    ErrorCode.RATE_LIMITED_LOGIN,
    ErrorCode.RATE_LIMITED_REFRESH,
    ErrorCode.RATE_LIMITED_ACCESS,
    ErrorCode.REFRESH_CONCURRENT,
}


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


@app.on_event("startup")
def _startup() -> None:
    get_service().ensure_seed_users()


@app.get("/")
def read_root():
    return {"Hello": "World"}


def _tokens_payload(issued) -> dict:
    return {
        "access_token": issued.access_token,
        "refresh_token": issued.refresh_token,
        "token_type": issued.token_type,
        "expires_in": issued.expires_in,
        "refresh_expires_in": issued.refresh_expires_in,
    }


@app.post("/auth/login")
def login(payload: LoginRequest, service: AuthService = Depends(get_service)):
    issued = service.login(payload.username, payload.password)
    return _tokens_payload(issued)


@app.post("/auth/refresh")
def refresh(payload: RefreshRequest, service: AuthService = Depends(get_service)):
    issued = service.refresh(payload.refresh_token)
    return _tokens_payload(issued)


@app.get("/protected/profile", dependencies=[Depends(require_scope("profile:read"))])
def read_profile():
    return {"resource": "profile", "data": {"theme": "dark"}}


@app.post("/protected/admin/action", dependencies=[Depends(require_scope("admin:action"))])
def admin_action():
    return {"resource": "admin-action", "executed": True}


@app.exception_handler(AuthError)
def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    code = exc.error_code
    body = {"error": code.value, "error_description": exc.message}
    path = request.url.path

    if path.startswith("/protected"):
        # 默认拒绝 + 不泄露资源存在性：所有认证授权失败统一为 404
        return JSONResponse(status_code=404, content={"detail": "Not Found", **body})

    status_code = 429 if code in _RATE_LIMITED_CODES else 401
    return JSONResponse(status_code=status_code, content=body)
