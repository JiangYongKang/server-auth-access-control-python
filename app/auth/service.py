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
    AccessSessionRevokedError,
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
    RefreshSessionRevokedError,
    RefreshTokenConsumedError,
    RefreshTokenExpiredError,
    RefreshTokenInvalidError,
    RefreshRateLimitedError,
    SessionNotFoundError,
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

# 会话吊销原因（写入 Session.revoke_reason，用于区分失败语义与审计）
REASON_REPLAY = "replay of consumed refresh token"
REASON_LOGOUT = "user_logout"
REASON_REVOKED = "user_revoked"
REASON_EVICTED = "evicted_by_session_limit"

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

    @contextmanager
    def _family_exclusive_blocking(self, family_id: str):
        """阻塞式获取 family 独占锁（撤销操作用）。

        撤销与在途刷新竞争时必须串行化且结果确定：撤销等待在途刷新结束后生效，
        生效之后该会话的刷新/访问一律被拒；不会出现撤销与刷新同时成功。
        """
        lock = self._family_lock(family_id)
        lock.acquire()
        lock_path = Path(self.store.db_path).with_name(f".family.{family_id}.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = lock_path.open("a+")
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()
            lock.release()

    # ------------------------------------------------------------------
    # 令牌签发
    # ------------------------------------------------------------------
    def _issue_tokens(self, username: str, scopes: list[str], now: float,
                      device_id: str | None = None) -> IssuedTokens:
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
            device_id=device_id,
            last_refresh_at=None,
            expires_at=now + cfg.refresh_token_ttl_seconds,
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
    # 会话活跃性判定（唯一事实源）
    # ------------------------------------------------------------------
    @staticmethod
    def _session_is_active(session: Session, now: float) -> bool:
        if session.revoked:
            return False
        # expires_at <= 0 为历史遗留记录（未记录过期时间），不视为过期
        if session.expires_at > 0 and now >= session.expires_at:
            return False
        return True

    # ------------------------------------------------------------------
    # 登录
    # ------------------------------------------------------------------
    def login(self, username: str, password: str, device_id: str | None = None,
              now: float | None = None) -> IssuedTokens:
        now = self.now() if now is None else now
        cfg = self.config
        key = RateLimiter.login_key(username)
        logger.info("login input: username=%s, device_id=%r, window=%ss, now=%.3f",
                    username, device_id, cfg.failure_window_seconds, now)

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
            self._cleanup_locked(now)
            issued = self._issue_tokens(username, list(user.scopes), now, device_id)
            evicted = self._enforce_session_limit(username, now)
            logger.info(
                "login decision: SUCCESS username=%s scopes=%s device_id=%r evicted=%s",
                username, user.scopes, device_id, evicted,
            )
            return issued

    def _enforce_session_limit(self, username: str, now: float) -> list[str]:
        """同一用户活跃会话数超过上限时，按建立时间从最旧开始逐出（吊销）。

        规则确定：上限 max_active_sessions_per_user；超出部分总是最旧的会话被逐出，
        被逐出会话的访问/刷新令牌立即失效，调用方可在会话列表与失败原因中观察到。
        """
        limit = self.config.max_active_sessions_per_user
        if limit <= 0:
            return []
        active = sorted(
            (s for s in self.store.db.sessions.values()
             if s.username == username and self._session_is_active(s, now)),
            key=lambda s: (s.created_at, s.session_id),
        )
        evicted: list[str] = []
        while len(active) > limit:
            victim = active.pop(0)
            victim.revoked = True
            victim.revoke_reason = REASON_EVICTED
            evicted.append(victim.session_id)
            logger.info(
                "session limit: EVICT user=%s session=%s created_at=%.3f (limit=%d)",
                username, victim.session_id, victim.created_at, limit,
            )
        return evicted

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
                        reason=REASON_REPLAY,
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

                # 会话已被吊销：重放导致的整族吊销与用户主动撤销/逐出给出不同原因
                if session is not None and session.revoked:
                    if session.revoke_reason == REASON_REPLAY:
                        logger.info(
                            "refresh decision: REFRESH_FAMILY_REVOKED family=%s reason=%s",
                            family_id, session.revoke_reason,
                        )
                        self._count_refresh_failure(key, now)
                        raise RefreshFamilyRevokedError()
                    logger.info(
                        "refresh decision: REFRESH_SESSION_REVOKED session=%s reason=%s",
                        session.session_id, session.revoke_reason,
                    )
                    self._count_refresh_failure(key, now)
                    raise RefreshSessionRevokedError()

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
                    session.last_refresh_at = now
                    session.expires_at = now + cfg.refresh_token_ttl_seconds
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
    # 会话管理：列表 / 登出 / 撤销 / 清理
    # ------------------------------------------------------------------
    def list_sessions(self, username: str, current_session_id: str | None = None,
                      now: float | None = None) -> list[dict]:
        """列出该用户名下所有仍活跃的会话（只含自己的，绝不返回他人会话）。"""
        now = self.now() if now is None else now
        with self.store:
            sessions = sorted(
                (s for s in self.store.db.sessions.values()
                 if s.username == username and self._session_is_active(s, now)),
                key=lambda s: (s.created_at, s.session_id),
            )
            result = [
                {
                    "session_id": s.session_id,
                    "device_id": s.device_id,
                    "created_at": s.created_at,
                    "last_refresh_at": s.last_refresh_at,
                    "is_current": s.session_id == current_session_id,
                }
                for s in sessions
            ]
        logger.info(
            "sessions list: user=%s count=%d current=%s",
            username, len(result), current_session_id,
        )
        return result

    def revoke_session(self, username: str, session_id: str, reason: str = REASON_REVOKED,
                       now: float | None = None) -> None:
        """撤销指定会话（仅限本人）。幂等：重复撤销结果一致，不会重新激活。

        会话不存在或不属于调用方时抛出 SessionNotFoundError，
        两种情况对外表现完全一致，无法借此探测他人会话是否存在。
        """
        now = self.now() if now is None else now
        with self.store:
            session = self.store.db.sessions.get(session_id)
            if session is None or session.username != username:
                logger.info(
                    "revoke decision: SESSION_NOT_FOUND user=%s session=%s known=%s",
                    username, session_id, session is not None,
                )
                raise SessionNotFoundError()
            family_id = session.family_id

        # 与在途刷新串行化：撤销生效后该会话的刷新/访问一律被拒
        with self._family_exclusive_blocking(family_id):
            with self.store:
                session = self.store.db.sessions.get(session_id)
                if session is None or session.username != username:
                    raise SessionNotFoundError()
                if session.revoked:
                    # 幂等：已撤销的会话保持原撤销原因与结果，不重新激活
                    logger.info(
                        "revoke decision: ALREADY_REVOKED session=%s reason=%s (idempotent)",
                        session_id, session.revoke_reason,
                    )
                    return
                session.revoked = True
                session.revoke_reason = reason
                logger.info(
                    "revoke decision: REVOKED user=%s session=%s reason=%s",
                    username, session_id, reason,
                )

    def logout(self, username: str, session_id: str, now: float | None = None) -> None:
        """登出当前会话。"""
        self.revoke_session(username, session_id, reason=REASON_LOGOUT, now=now)

    def revoke_other_sessions(self, username: str, current_session_id: str,
                              now: float | None = None) -> int:
        """撤销本人除当前会话外的全部活跃会话，返回撤销数量。"""
        now = self.now() if now is None else now
        with self.store:
            targets = [
                s for s in self.store.db.sessions.values()
                if s.username == username
                and s.session_id != current_session_id
                and not s.revoked
            ]
        revoked = 0
        for target in targets:
            # 逐个走同一撤销路径，保证与在途刷新串行化且幂等
            self.revoke_session(username, target.session_id, reason=REASON_REVOKED, now=now)
            revoked += 1
        logger.info(
            "revoke others: user=%s keep=%s revoked=%d",
            username, current_session_id, revoked,
        )
        return revoked

    def cleanup(self, now: float | None = None) -> dict[str, int]:
        """清理过期/已撤销的会话与令牌记录，以及过期的限流状态（结果落盘）。

        只删除：已撤销的会话、已过期的会话、已过期的刷新令牌记录、
        所属会话已不存在的刷新令牌记录、窗口已结束且未锁定的限流状态。
        仍在有效期内的会话与令牌（含已消费但未过期的重放检测证据）一律保留。
        """
        now = self.now() if now is None else now
        with self.store:
            return self._cleanup_locked(now)

    def _cleanup_locked(self, now: float) -> dict[str, int]:
        """cleanup 的临界区内版本；调用方必须已持有 store 锁。"""
        removed = {"sessions": 0, "refresh_tokens": 0, "rate_limits": 0}
        db = self.store.db
        dead_sessions = [
            sid for sid, s in db.sessions.items()
            if s.revoked or (s.expires_at > 0 and now >= s.expires_at)
        ]
        for sid in dead_sessions:
            del db.sessions[sid]
            removed["sessions"] += 1
        dead_tokens = [
            jti for jti, r in db.refresh_tokens.items()
            if now >= r.expires_at or r.session_id not in db.sessions
        ]
        for jti in dead_tokens:
            del db.refresh_tokens[jti]
            removed["refresh_tokens"] += 1
        window = self.config.failure_window_seconds
        dead_limits = [
            key for key, st in db.rate_limits.items()
            if st.locked_until <= now and now - st.window_start >= window
        ]
        for key in dead_limits:
            del db.rate_limits[key]
            removed["rate_limits"] += 1
        if any(removed.values()):
            logger.info("cleanup: removed=%s now=%.3f", removed, now)
        return removed

    # ------------------------------------------------------------------
    # 受保护资源访问判定（默认拒绝）
    # ------------------------------------------------------------------
    def authenticate(self, authorization_header: str | None,
                     now: float | None = None) -> AccessTokenClaims:
        """校验访问令牌并返回完整 claims（会话管理端点用，不做作用域判定）。"""
        return self._authorize_claims(authorization_header, None, now)

    def authorize(self, authorization_header: str | None, required_scope: str,
                  now: float | None = None) -> str:
        claims = self._authorize_claims(authorization_header, required_scope, now)
        return claims.sub

    def _authorize_claims(self, authorization_header: str | None,
                          required_scope: str | None,
                          now: float | None = None) -> AccessTokenClaims:
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

            # 会话撤销即时生效：已撤销/已清理的会话，其访问令牌立即失效，
            # 不等访问令牌自然到期
            session = self.store.db.sessions.get(claims.session_id)
            if session is None or session.revoked:
                reason = session.revoke_reason if session is not None else "session gone"
                err = AccessSessionRevokedError(
                    f"session={claims.session_id} reason={reason}"
                )
                logger.info(
                    "authorize decision: DENY subject=%s reason=access_session_revoked (%s)",
                    claims.sub, reason,
                )
                self._access_failure(claims.sub, err, now)
                raise err

            if required_scope is not None and required_scope not in claims.scopes:
                err = AccessScopeInsufficientError(
                    f"required={required_scope} granted={claims.scopes}"
                )
                self._access_failure(claims.sub, err, now)
                raise err

            logger.info("authorize decision: ALLOW subject=%s scope=%s jti=%s",
                        claims.sub, required_scope, claims.jti)
            return claims

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
