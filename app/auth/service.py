"""认证服务：凭据校验、令牌签发、刷新轮换与访问判定。

并发控制（刷新轮换的关键）：
1. 进程内：每个 family 一把非阻塞互斥锁，同一 family 的两个并发刷新，
   只有第一个能进入临界区，另一个立即得到 refresh_concurrent；
2. 跨进程：以 db_path 同目录下的 family 锁文件做 flock 非阻塞互斥，
   保证进程重启/多进程并发下也只有一个刷新成功；
3. 状态判定与落盘在 JsonStore 临界区内原子完成。

所有时间通过参数 now 显式注入，保证重复运行结果确定、可复现。
关键判定以 logging 打印输入与判定依据。
"""
from __future__ import annotations

import fcntl
import logging
import os
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from app.auth import security
from app.auth.errors import (
    AccessRateLimitedError,
    AccessScopeInsufficientError,
    AccessTokenExpiredError,
    AccessTokenForgeryError,
    AccessTokenMalformedError,
    AccessTokenMissingError,
    AccessTokenSignatureInvalidError,
    AccountLockedError,
    AuthError,
    InvalidCredentialsError,
    LoginRateLimitedError,
    RefreshConcurrentError,
    RefreshFamilyRevokedError,
    RefreshTokenConsumedError,
    RefreshTokenExpiredError,
    RefreshTokenInvalidError,
    RefreshRateLimitedError,
)
from app.auth.models import (
    AccessTokenClaims,
    AuthConfig,
    IssuedTokens,
    RefreshTokenRecord,
    Session,
)
from app.auth.rate_limit import RateLimiter
from app.auth.store import JsonStore

logger = logging.getLogger("app.auth")

_SEED_USERS = (
    ("admin", "admin-password", ["profile:read", "admin:action"]),
    ("alice", "alice-password", ["profile:read"]),
    ("bob", "bob-password", []),
)


class AuthService:
    def __init__(self, config: AuthConfig, store: JsonStore, rate_limiter: RateLimiter) -> None:
        self.config = config
        self.store = store
        self.rate_limiter = rate_limiter
        self._family_locks: dict[str, threading.Lock] = {}
        self._family_locks_guard = threading.Lock()

    # ------------------------------------------------------------------
    # 初始化 / 时间
    # ------------------------------------------------------------------
    def ensure_seed_users(self) -> None:
        with self.store:
            if self.store.db.users:
                return
            for username, password, scopes in _SEED_USERS:
                salt = security.new_salt()
                self.store.db.users[username] = self._models_user(
                    username, security.hash_password(password, salt), salt, scopes
                )
        logger.info("seed users initialized: %s", [u[0] for u in _SEED_USERS])

    @staticmethod
    def _models_user(username: str, password_hash: str, salt: str, scopes: list[str]):
        from app.auth.models import User

        return User(username=username, password_hash=password_hash,
                    password_salt=salt, scopes=list(scopes), enabled=True)

    def now(self) -> float:
        return time.time()

    # ------------------------------------------------------------------
    # family 并发互斥：进程内锁 + 跨进程 flock
    # ------------------------------------------------------------------
    def _family_lock(self, family_id: str) -> threading.Lock:
        with self._family_locks_guard:
            lock = self._family_locks.get(family_id)
            if lock is None:
                lock = threading.Lock()
                self._family_locks[family_id] = lock
            return lock

    @contextmanager
    def _family_exclusive(self, family_id: str):
        """获取 family 独占锁；获取失败（有并发刷新在途）抛出 RefreshConcurrentError。"""
        lock = self._family_lock(family_id)
        if not lock.acquire(blocking=False):
            yield False
            return
        lock_path = Path(self.store.db_path).with_name(f".family.{family_id}.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = lock_path.open("a+")
        try:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()
            lock.release()

    # ------------------------------------------------------------------
    # 令牌签发
    # ------------------------------------------------------------------
    def _issue_tokens(self, username: str, scopes: list[str], now: float) -> IssuedTokens:
        cfg = self.config
        session_id = uuid.uuid4().hex
        family_id = uuid.uuid4().hex
        access_jti = uuid.uuid4().hex
        refresh_jti = uuid.uuid4().hex

        claims = AccessTokenClaims(
            sub=username,
            jti=access_jti,
            session_id=session_id,
            family_id=family_id,
            scopes=list(scopes),
            iat=now,
            exp=now + cfg.access_token_ttl_seconds,
        )
        access_token = security.encode_access_token(cfg.secret, claims)
        refresh_token = security.encode_refresh_token(cfg.secret, refresh_jti, family_id)

        self.store.db.sessions[session_id] = Session(
            session_id=session_id,
            username=username,
            family_id=family_id,
            issued_jti=refresh_jti,
            revoked=False,
            revoke_reason=None,
            created_at=now,
        )
        self.store.db.refresh_tokens[refresh_jti] = RefreshTokenRecord(
            jti=refresh_jti,
            family_id=family_id,
            session_id=session_id,
            username=username,
            consumed=False,
            expires_at=now + cfg.refresh_token_ttl_seconds,
        )
        return IssuedTokens(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=cfg.access_token_ttl_seconds,
            refresh_expires_in=cfg.refresh_token_ttl_seconds,
        )

    # ------------------------------------------------------------------
    # 登录
    # ------------------------------------------------------------------
    def login(self, username: str, password: str, now: float | None = None) -> IssuedTokens:
        now = self.now() if now is None else now
        cfg = self.config
        key = RateLimiter.login_key(username)
        logger.info("login input: username=%s, window=%ss, now=%.3f", username,
                    cfg.failure_window_seconds, now)

        with self.store:
            if self.rate_limiter.is_locked(key, cfg.failure_window_seconds, now):
                logger.info("login decision: RATE_LIMITED key=%s", key)
                raise LoginRateLimitedError()

            user = self.store.db.users.get(username)
            valid = (
                user is not None
                and user.enabled
                and security.verify_password(password, user.password_salt, user.password_hash)
            )
            if not valid:
                state = self.rate_limiter.record_failure(
                    key, cfg.login_max_failures, cfg.login_lock_seconds,
                    cfg.failure_window_seconds, now,
                )
                if user is not None and not user.enabled:
                    logger.info("login decision: ACCOUNT_LOCKED(username disabled) failures=%d",
                                state.failures)
                    raise AccountLockedError()
                logger.info("login decision: INVALID_CREDENTIALS failures=%d/%d locked_until=%.3f",
                            state.failures, cfg.login_max_failures, state.locked_until)
                # 本次失败把计数推到阈值：立即进入锁定并明确拒绝
                if state.locked_until > now:
                    raise LoginRateLimitedError()
                raise InvalidCredentialsError()

            self.rate_limiter.reset(key)
            issued = self._issue_tokens(username, list(user.scopes), now)
            logger.info("login decision: SUCCESS username=%s scopes=%s", username, user.scopes)
            return issued

    # ------------------------------------------------------------------
    # 刷新：轮换 + 重放检测 + 会话整体吊销
    # ------------------------------------------------------------------
    def refresh(self, refresh_token: str, now: float | None = None) -> IssuedTokens:
        now = self.now() if now is None else now
        cfg = self.config

        try:
            jti, family_id = security.decode_refresh_token(cfg.secret, refresh_token)
        except RefreshTokenInvalidError:
            logger.info("refresh decision: REFRESH_TOKEN_INVALID (envelope undecodable)")
            raise

        with self._family_exclusive(family_id) as acquired:
            if not acquired:
                logger.info("refresh decision: REFRESH_CONCURRENT family=%s jti=%s",
                            family_id, jti)
                raise RefreshConcurrentError()

            with self.store:
                record = self.store.db.refresh_tokens.get(jti)
                if record is None or record.family_id != family_id:
                    logger.info("refresh decision: REFRESH_TOKEN_INVALID jti=%s known=%s",
                                jti, record is not None)
                    raise RefreshTokenInvalidError("refresh token is not recognized")

                key = RateLimiter.refresh_key(record.username)
                if self.rate_limiter.is_locked(key, cfg.failure_window_seconds, now):
                    logger.info("refresh decision: RATE_LIMITED_REFRESH key=%s", key)
                    raise RefreshRateLimitedError()

                session = self.store.db.sessions.get(record.session_id)

                # 重放检测优先：已消费令牌再次出现 => 攻击者重放 => 整个 family 失效
                if record.consumed:
                    self._revoke_family(
                        record, session, now,
                        reason="replay of consumed refresh token",
                    )
                    logger.info(
                        "refresh decision: REFRESH_TOKEN_CONSUMED jti=%s -> family=%s REVOKED",
                        jti, family_id,
                    )
                    state = self.rate_limiter.record_failure(
                        key, cfg.refresh_max_failures, cfg.refresh_lock_seconds,
                        cfg.failure_window_seconds, now,
                    )
                    if state.locked_until > now:
                        raise RefreshRateLimitedError()
                    raise RefreshTokenConsumedError()

                # family 已被吊销（例如另一条令牌的重放导致整族失效）
                if session is not None and session.revoked:
                    logger.info("refresh decision: REFRESH_FAMILY_REVOKED family=%s reason=%s",
                                family_id, session.revoke_reason)
                    self._count_refresh_failure(key, now)
                    raise RefreshFamilyRevokedError()

                if now >= record.expires_at:
                    logger.info("refresh decision: REFRESH_TOKEN_EXPIRED jti=%s exp=%.3f now=%.3f",
                                jti, record.expires_at, now)
                    self._count_refresh_failure(key, now)
                    raise RefreshTokenExpiredError()

                # 轮换：旧令牌消费，签发同一 session/family 下的新令牌对
                record.consumed = True
                user = self.store.db.users.get(record.username)
                scopes = list(user.scopes) if user is not None else []
                new_refresh_jti = uuid.uuid4().hex
                new_access_jti = uuid.uuid4().hex
                claims = AccessTokenClaims(
                    sub=record.username,
                    jti=new_access_jti,
                    session_id=record.session_id,
                    family_id=family_id,
                    scopes=scopes,
                    iat=now,
                    exp=now + cfg.access_token_ttl_seconds,
                )
                new_access = security.encode_access_token(cfg.secret, claims)
                new_refresh = security.encode_refresh_token(cfg.secret, new_refresh_jti, family_id)
                self.store.db.refresh_tokens[new_refresh_jti] = RefreshTokenRecord(
                    jti=new_refresh_jti,
                    family_id=family_id,
                    session_id=record.session_id,
                    username=record.username,
                    consumed=False,
                    expires_at=now + cfg.refresh_token_ttl_seconds,
                )
                if session is not None:
                    session.issued_jti = new_refresh_jti
                self.rate_limiter.reset(key)
                logger.info(
                    "refresh decision: ROTATED family=%s old_jti=%s consumed new_jti=%s",
                    family_id, jti, new_refresh_jti,
                )
                return IssuedTokens(
                    access_token=new_access,
                    refresh_token=new_refresh,
                    expires_in=cfg.access_token_ttl_seconds,
                    refresh_expires_in=cfg.refresh_token_ttl_seconds,
                )

    def _count_refresh_failure(self, key: str, now: float) -> None:
        cfg = self.config
        state = self.rate_limiter.record_failure(
            key, cfg.refresh_max_failures, cfg.refresh_lock_seconds,
            cfg.failure_window_seconds, now,
        )
        if state.locked_until > now:
            raise RefreshRateLimitedError()

    def _revoke_family(self, record: RefreshTokenRecord, session: Session | None,
                       now: float, reason: str) -> None:
        # 只吊销会话（family），不把未消费的令牌误标为 consumed：
        # - 被重放的那张令牌自身保持 consumed=True -> 重放得到 consumed 原因；
        # - 族内其他未消费令牌 -> family_revoked 原因，两者可区分。
        if session is not None:
            session.revoked = True
            session.revoke_reason = reason

    # ------------------------------------------------------------------
    # 受保护资源访问判定（默认拒绝）
    # ------------------------------------------------------------------
    def authorize(self, authorization_header: str | None, required_scope: str,
                  now: float | None = None) -> str:
        now = self.now() if now is None else now
        cfg = self.config
        logger.info("authorize input: header_present=%s required_scope=%s now=%.3f",
                    authorization_header is not None, required_scope, now)

        # 频次状态必须在 store 临界区内读写，判定结果才会随每次变更落盘
        with self.store:
            token = self._extract_bearer(authorization_header)

            claims: AccessTokenClaims | None = None
            failure: AuthError | None = None
            try:
                claims = security.decode_access_token(cfg.secret, token, now)
            except AuthError as exc:  # 五类令牌失败均可区分
                failure = exc

            if claims is None:
                self._access_failure("unknown", failure, now)
                raise failure  # type: ignore[misc]

            key = RateLimiter.access_key(claims.sub)
            if self.rate_limiter.is_locked(key, cfg.failure_window_seconds, now):
                logger.info("authorize decision: RATE_LIMITED_ACCESS subject=%s", claims.sub)
                raise AccessRateLimitedError()

            if required_scope not in claims.scopes:
                err = AccessScopeInsufficientError(
                    f"required={required_scope} granted={claims.scopes}"
                )
                self._access_failure(claims.sub, err, now)
                raise err

            logger.info("authorize decision: ALLOW subject=%s scope=%s jti=%s",
                        claims.sub, required_scope, claims.jti)
            return claims.sub

    @staticmethod
    def _extract_bearer(header: str | None) -> str:
        if header is None or not header:
            raise AccessTokenMissingError()
        parts = header.split(" ", 1)
        if len(parts) != 2 or parts[0] != "Bearer" or not parts[1].strip():
            raise AccessTokenMalformedError("authorization header is not a Bearer token")
        token = parts[1].strip()
        # 凭证必须形如本系统签发的两段信封；整体结构不符（如标准三段 JWT、
        # 无分隔随机串）属于伪造/张冠李戴，与“结构在但字段坏”的 malformed 区分。
        if len(token.split(".")) != 2:
            raise AccessTokenForgeryError("token does not match the issuer's token shape")
        return token

    def _access_failure(self, subject: str, err: AuthError, now: float) -> None:
        cfg = self.config
        key = RateLimiter.access_key(subject)
        state = self.rate_limiter.record_failure(
            key, cfg.access_max_failures, cfg.access_lock_seconds,
            cfg.failure_window_seconds, now,
        )
        logger.info(
            "authorize decision: DENY subject=%s reason=%s failures=%d/%d locked_until=%.3f",
            subject, err.error_code.value, state.failures, cfg.access_max_failures,
            state.locked_until,
        )
        if state.locked_until > now:
            raise AccessRateLimitedError() from err
