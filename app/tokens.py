"""自包含的 HMAC-SHA256 签名令牌（JWT 风格）签发与校验。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field

from app.errors import AuthError, FailureReason

_ALG = "HS256"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


@dataclass(frozen=True)
class TokenClaims:
    """访问令牌载荷。"""

    sub: str
    sid: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    exp: int = 0
    iat: int = 0
    jti: str = ""
    typ: str = "access"


def _sign(secret: str, signing_input: str) -> str:
    mac = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256)
    return _b64e(mac.digest())


def encode_access_token(
    secret: str, sub: str, sid: str, scopes: frozenset[str],
    now: int, ttl: int, jti: str,
) -> str:
    """签发访问令牌。"""
    header = _b64e(json.dumps({"alg": _ALG, "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64e(json.dumps({
        "sub": sub, "sid": sid, "scopes": sorted(scopes),
        "iat": now, "exp": now + ttl, "jti": jti, "typ": "access",
    }, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}"
    return f"{signing_input}.{_sign(secret, signing_input)}"


def decode_token(secret: str, token: str, now: int) -> TokenClaims:
    """校验并解析令牌；失败抛出携带可区分原因的 AuthError。"""
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError(FailureReason.TOKEN_INVALID, "令牌格式错误")
    header_b64, payload_b64, sig = parts
    expected = _sign(secret, f"{header_b64}.{payload_b64}")
    if not hmac.compare_digest(expected, sig):
        raise AuthError(FailureReason.TOKEN_INVALID, "签名无效或令牌被伪造")
    try:
        payload = json.loads(_b64d(payload_b64))
        exp = int(payload["exp"])
        claims = TokenClaims(
            sub=str(payload["sub"]),
            sid=str(payload["sid"]),
            scopes=frozenset(payload.get("scopes", [])),
            exp=exp,
            iat=int(payload.get("iat", 0)),
            jti=str(payload.get("jti", "")),
            typ=str(payload.get("typ", "")),
        )
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise AuthError(FailureReason.TOKEN_INVALID, "令牌载荷无法解析") from None
    if now >= claims.exp:
        raise AuthError(FailureReason.TOKEN_EXPIRED, "令牌已过期")
    return claims


def new_refresh_token() -> str:
    """生成不透明刷新令牌。"""
    return secrets.token_urlsafe(32)


def hash_refresh_token(token: str) -> str:
    """刷新令牌落盘前的散列。"""
    return hashlib.sha256(token.encode()).hexdigest()
