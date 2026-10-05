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
    # 客户端自报的设备/客户端标识，可选；不携带时行为与旧版完全一致
    client_id: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


class RevokeSessionRequest(BaseModel):
    session_id: str


@app.on_event("startup")
def _startup() -> None:
    get_service().ensure_seed_users()


@app.get("/")
def read_root():
    return {"Hello": "World"}


def _tokens_payload(issued) -> dict:
    payload = {
        "access_token": issued.access_token,
        "refresh_token": issued.refresh_token,
        "token_type": issued.token_type,
        "expires_in": issued.expires_in,
        "refresh_expires_in": issued.refresh_expires_in,
        "session_id": issued.session_id,
    }
    if issued.evicted_sessions:
        # 会话数量上限被触发：明确告知调用方哪些旧会话被驱逐
        payload["evicted_sessions"] = list(issued.evicted_sessions)
    return payload


@app.post("/auth/login")
def login(payload: LoginRequest, service: AuthService = Depends(get_service)):
    issued = service.login(payload.username, payload.password,
                           client_label=payload.client_id)
    return _tokens_payload(issued)


@app.post("/auth/refresh")
def refresh(payload: RefreshRequest, service: AuthService = Depends(get_service)):
    issued = service.refresh(payload.refresh_token)
    return _tokens_payload(issued)


def _bearer_header(request: Request) -> str | None:
    return request.headers.get("authorization")


@app.get("/auth/sessions")
def list_sessions(request: Request, service: AuthService = Depends(get_service)):
    infos = service.list_sessions(_bearer_header(request))
    return {
        "sessions": [
            {
                "session_id": i.session_id,
                "client_id": i.client_label,
                "created_at": i.created_at,
                "last_refresh_at": i.last_refresh_at,
                "is_current": i.is_current,
            }
            for i in infos
        ]
    }


@app.post("/auth/logout")
def logout(request: Request, service: AuthService = Depends(get_service)):
    session_id = service.logout(_bearer_header(request))
    return {"revoked": True, "session_id": session_id}


@app.post("/auth/sessions/revoke")
def revoke_session(payload: RevokeSessionRequest, request: Request,
                   service: AuthService = Depends(get_service)):
    # 对他人/不存在的会话不做任何变更，响应与成功一致，不泄露目标是否存在
    service.revoke_session(_bearer_header(request), payload.session_id)
    return {"revoked": True, "session_id": payload.session_id}


@app.post("/auth/sessions/revoke-others")
def revoke_other_sessions(request: Request, service: AuthService = Depends(get_service)):
    revoked = service.revoke_other_sessions(_bearer_header(request))
    return {"revoked": True, "revoked_sessions": revoked}


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
