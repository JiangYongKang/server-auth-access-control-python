"""认证服务：凭据校验、令牌签发/轮换、作用域判定。"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass

from app.errors import AuthError, FailureReason
from app.ratelimit import RateLimiter
from app.store import Session, Store, UserRecord
from app.tokens import (
    TokenClaims,
    decode_token,
    encode_access_token,
    hash_refresh_token,
    new_refresh_token,
)

_PBKDF2_ROUNDS = 100_000


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    sid: str
    scopes: frozenset[str]


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ROUNDS
    ).hex()


class AuthService:
    def __init__(
        self, store: Store, limiter: RateLimiter, *,
        secret: str, access_ttl: int, refresh_ttl: int,
    ) -> None:
        self._store = store
        self._limiter = limiter
        self._secret = secret
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        # 序列化刷新临界区：同一主体的并发刷新只有一个能完成检查-消费
        self._refresh_lock = threading.Lock()

    def register(self, sub: str, password: str, scopes: list[str]) -> None:
        salt = secrets.token_hex(16)
        self._store.put_user(UserRecord(
            sub=sub, salt=salt,
            password_hash=_hash_password(password, salt),
            scopes=sorted(set(scopes)),
        ))

    def _issue(self, sub: str, sid: str, scopes: frozenset[str], now: int,
               consumed: list[str] | None = None) -> TokenPair:
        refresh_token = new_refresh_token()
        self._store.put_session(Session(
            sid=sid, sub=sub, revoked=False,
            refresh_hash=hash_refresh_token(refresh_token),
            refresh_exp=now + self._refresh_ttl,
            consumed_hashes=list(consumed or []),
        ))
        access = encode_access_token(
            self._secret, sub, sid, scopes, now, self._access_ttl,
            jti=secrets.token_hex(8),
        )
        return TokenPair(access, refresh_token, sid, scopes)

    def login(self, sub: str, password: str, now: int) -> TokenPair:
        key = f"login:{sub}"
        self._limiter.check(key, now)
        user = self._store.get_user(sub)
        ok = user is not None and hmac.compare_digest(
            user.password_hash, _hash_password(password, user.salt)
        )
        if not ok:
            self._limiter.record_failure(key, now)
            raise AuthError(FailureReason.INVALID_CREDENTIALS, "用户名或密码错误")
        self._limiter.reset(key)
        return self._issue(sub, secrets.token_hex(16), frozenset(user.scopes), now)

    def refresh(self, refresh_token: str, now: int) -> TokenPair:
        """轮换刷新令牌；重放已消费令牌会使整个会话失效。"""
        with self._refresh_lock:
            presented = hash_refresh_token(refresh_token)
            session = self._store.find_session_by_refresh(presented)
            if session is None:
                raise AuthError(FailureReason.REFRESH_TOKEN_UNKNOWN, "刷新令牌不存在")
            key = f"refresh:{session.sub}"
            self._limiter.check(key, now)
            if session.revoked:
                raise AuthError(FailureReason.SESSION_REVOKED, "会话已失效")
            if presented in session.consumed_hashes:
                # 重放检测：已消费的刷新令牌被再次使用，整个会话作废
                session.revoked = True
                self._store.put_session(session)
                self._limiter.record_failure(key, now)
                raise AuthError(FailureReason.REFRESH_TOKEN_REUSED, "刷新令牌已被消费")
            if now >= session.refresh_exp:
                raise AuthError(FailureReason.TOKEN_EXPIRED, "刷新令牌已过期")
            user = self._store.get_user(session.sub)
            scopes = frozenset(user.scopes) if user else frozenset()
            # 轮换：旧令牌进入消费历史（立即失效），签发新令牌
            consumed = [*session.consumed_hashes, session.refresh_hash]
            self._limiter.reset(key)
            return self._issue(session.sub, session.sid, scopes, now, consumed=consumed)

    def authenticate(self, access_token: str, now: int) -> TokenClaims:
        """校验访问令牌并确认会话未失效。"""
        claims = decode_token(self._secret, access_token, now)
        if claims.typ != "access":
            raise AuthError(FailureReason.TOKEN_TYPE_MISMATCH, "令牌类型不符")
        session = self._store.get_session(claims.sid)
        if session is None or session.revoked:
            raise AuthError(FailureReason.SESSION_REVOKED, "会话已失效")
        return claims

    def authorize(self, access_token: str, required: set[str], now: int) -> TokenClaims:
        """默认拒绝：缺少任一所需作用域即抛 INSUFFICIENT_SCOPE。"""
        claims = self.authenticate(access_token, now)
        if not set(required) <= set(claims.scopes):
            raise AuthError(FailureReason.INSUFFICIENT_SCOPE, "缺少所需作用域")
        return claims
