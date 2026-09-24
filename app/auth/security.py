"""密码哈希与访问令牌（HMAC 签名，自包含实现，不依赖外部 JWT 库）。

令牌格式：base64url(payload_json).base64url(hmac_sha256(secret, payload_b64))
只分两段（无独立 header 段），因此：
- 三段式但内容无法解析 -> 伪造（forgery）
- 两段式但字段非法     -> 结构错误（malformed）
- 结构正确但签名不符   -> 签名无效（signature_invalid）
- 一切合法但 exp 已过  -> 过期（expired）
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

from app.auth.errors import (
    AccessTokenExpiredError,
    AccessTokenForgeryError,
    AccessTokenMalformedError,
    AccessTokenSignatureInvalidError,
    RefreshTokenInvalidError,
)
from app.auth.models import AccessTokenClaims

_PBKDF2_ROUNDS = 200_000


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def new_salt() -> str:
    return _b64e(os.urandom(16))


def hash_password(password: str, salt: str, rounds: int = _PBKDF2_ROUNDS) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), rounds
    )
    return f"pbkdf2_sha256${rounds}${_b64e(digest)}"


def verify_password(
    password: str, salt: str, expected_hash: str, rounds: int = _PBKDF2_ROUNDS
) -> bool:
    try:
        algo, round_str, _digest = expected_hash.split("$", 2)
        if algo != "pbkdf2_sha256":
            return False
        candidate = hash_password(password, salt, int(round_str))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected_hash)


def sign_payload(secret: str, payload_b64: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256)
    return _b64e(mac.digest())


def encode_access_token(secret: str, claims: AccessTokenClaims) -> str:
    payload = {
        "sub": claims.sub,
        "jti": claims.jti,
        "sid": claims.session_id,
        "fid": claims.family_id,
        "sco": list(claims.scopes),
        "iat": claims.iat,
        "exp": claims.exp,
        "typ": "access",
    }
    payload_b64 = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature_b64 = sign_payload(secret, payload_b64)
    return f"{payload_b64}.{signature_b64}"


def _parse_claims(payload: object) -> AccessTokenClaims:
    if not isinstance(payload, dict):
        raise AccessTokenMalformedError("token payload is not a JSON object")
    required = ("sub", "jti", "sid", "fid", "sco", "iat", "exp", "typ")
    if any(key not in payload for key in required):
        raise AccessTokenMalformedError("token payload is missing required fields")
    if payload["typ"] != "access":
        raise AccessTokenForgeryError("token type is not an access token")
    if not isinstance(payload["sub"], str) or not isinstance(payload["jti"], str):
        raise AccessTokenMalformedError("token subject/jti must be strings")
    if not isinstance(payload["sid"], str) or not isinstance(payload["fid"], str):
        raise AccessTokenMalformedError("token session/family id must be strings")
    if not isinstance(payload["sco"], list) or not all(
        isinstance(s, str) for s in payload["sco"]
    ):
        raise AccessTokenMalformedError("token scopes must be a list of strings")
    if not isinstance(payload["iat"], (int, float)) or not isinstance(
        payload["exp"], (int, float)
    ):
        raise AccessTokenMalformedError("token timestamps must be numbers")
    return AccessTokenClaims(
        sub=payload["sub"],
        jti=payload["jti"],
        session_id=payload["sid"],
        family_id=payload["fid"],
        scopes=list(payload["sco"]),
        iat=float(payload["iat"]),
        exp=float(payload["exp"]),
    )


def decode_access_token(secret: str, token: str, now: float) -> AccessTokenClaims:
    """校验并解码访问令牌，按结构 -> 签名 -> 过期的顺序给出可区分失败原因。"""
    if not isinstance(token, str) or not token:
        raise AccessTokenMalformedError("token is empty")

    parts = token.split(".")
    if len(parts) != 2:
        # 典型的三段式 JWT 或随机串：尝试解析者在伪造一个本系统令牌
        raise AccessTokenForgeryError("token does not match the issuer's token shape")

    payload_b64, signature_b64 = parts
    try:
        payload_bytes = _b64d(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise AccessTokenMalformedError("token payload cannot be decoded")

    # 结构解析通过后再验签：字段缺失/类型错误归 malformed
    claims = _parse_claims(payload)

    expected_sig = sign_payload(secret, payload_b64)
    if not hmac.compare_digest(expected_sig, signature_b64):
        raise AccessTokenSignatureInvalidError("token signature does not match")

    if now >= claims.exp:
        raise AccessTokenExpiredError(
            f"token expired at {claims.exp:f}, now={now:f}"
        )
    return claims


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------------------
# 刷新令牌信封
#
# 刷新令牌本身不携带可用权限，只作为“服务端记录”的不透明索引。
# 但信封经过 HMAC 签名，使 family_id 可在查库前被可信地取出
# （用于对同一 family 的并发刷新做互斥），同时防止调用方伪造 family 归属。
# 格式：base64url({"jti", "fid"}).base64url(hmac)
# ---------------------------------------------------------------------------
def encode_refresh_token(secret: str, jti: str, family_id: str) -> str:
    payload = {"jti": jti, "fid": family_id, "typ": "refresh"}
    payload_b64 = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return f"{payload_b64}.{sign_payload(secret, payload_b64)}"


def decode_refresh_token(secret: str, token: str) -> tuple[str, str]:
    """返回 (jti, family_id)；任何结构/签名问题统一为 refresh_token_invalid。"""
    if not isinstance(token, str) or not token:
        raise RefreshTokenInvalidError("refresh token is empty")
    parts = token.split(".")
    if len(parts) != 2:
        raise RefreshTokenInvalidError("refresh token has wrong shape")
    payload_b64, signature_b64 = parts
    if not hmac.compare_digest(sign_payload(secret, payload_b64), signature_b64):
        raise RefreshTokenInvalidError("refresh token signature mismatch")
    try:
        payload = json.loads(_b64d(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise RefreshTokenInvalidError("refresh token payload cannot be decoded")
    if not isinstance(payload, dict) or payload.get("typ") != "refresh":
        raise RefreshTokenInvalidError("refresh token payload type mismatch")
    jti = payload.get("jti")
    family_id = payload.get("fid")
    if not isinstance(jti, str) or not isinstance(family_id, str):
        raise RefreshTokenInvalidError("refresh token payload fields invalid")
    return jti, family_id
