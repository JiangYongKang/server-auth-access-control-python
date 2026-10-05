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
    SessionRevokedError,
)
from app.auth.models import (
    AccessTokenClaims,
    AuthConfig,
    IssuedTokens,
    RefreshTokenRecord,
    Session,
    SessionInfo,
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
    def _issue_tokens(self, username: str, scopes: list[str], now: float,
                      client_label: str | None = None) -> IssuedTokens:
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
            client_label=client_label,
            last_refresh_at=0.0,
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
            session_id=session_id,
        )

    # ------------------------------------------------------------------
    # 登录
    # ------------------------------------------------------------------
    def login(self, username: str, password: str, client_label: str | None = None,
              now: float | None = None) -> IssuedTokens:
        now = self.now() if now is None else now
        cfg = self.config
        key = RateLimiter.login_key(username)
        logger.info("login input: username=%s client_label=%r window=%ss now=%.3f",
                    username, client_label, cfg.failure_window_seconds, now)

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
            evicted = self._enforce_session_cap(username, now)
            issued = self._issue_tokens(username, list(user.scopes), now,
                                        client_label=client_label)
            issued.evicted_sessions = evicted
            logger.info("login decision: SUCCESS username=%s scopes=%s session=%s evicted=%s",
                        username, user.scopes, issued.session_id, evicted)
            return issued

    # ------------------------------------------------------------------
    # 会话存活判定与数量上限
    # ------------------------------------------------------------------
    @staticmethod
    def _session_alive(session: Session, now: float) -> bool:
        return not session.revoked and now < session.expires_at

    def _alive_sessions(self, username: str, now: float) -> list[Session]:
        return [
            s for s in self.store.db.sessions.values()
            if s.username == username and self._session_alive(s, now)
        ]

    def _enforce_session_cap(self, username: str, now: float) -> list[str]:
        """登录签发新会话前调用：若加上新会话将超限，按创建时间（再按 id）从旧到新
        撤销最旧的存活会话，返回被驱逐的会话 id 列表（确定性规则）。"""
        cap = self.config.max_active_sessions_per_user
        alive = self._alive_sessions(username, now)
        overflow = len(alive) + 1 - cap
        if overflow <= 0:
            return []
        alive.sort(key=lambda s: (s.created_at, s.session_id))
        evicted: list[str] = []
        for session in alive[:overflow]:
            self._revoke_session_record(session, reason="session_cap_evicted")
            evicted.append(session.session_id)
        logger.info("session cap: user=%s cap=%d alive=%d -> evicted=%s",
                    username, cap, len(alive), evicted)
        return evicted

    @staticmethod
    def _revoke_session_record(session: Session, reason: str) -> None:
        # 幂等：已撤销的会话保持原撤销原因，不被覆盖、不被重新激活
        if session.revoked:
            return
        session.revoked = True
        session.revoke_reason = reason

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

                # family 已被吊销（重放检测、用户撤销或会话已被清理）：
                # 一律拒绝，撤销生效后绝不再签出新令牌
                if session is None:
                    logger.info("refresh decision: REFRESH_FAMILY_REVOKED family=%s "
                                "(session already removed)", family_id)
                    self._count_refresh_failure(key, now)
                    raise RefreshFamilyRevokedError("session no longer exists")
                if session.revoked:
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
                session.issued_jti = new_refresh_jti
                session.last_refresh_at = now
                # 会话存活期随每次成功轮换顺延一个刷新周期
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
                    session_id=record.session_id,
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
    def authenticate(self, authorization_header: str | None,
                     now: float | None = None) -> AccessTokenClaims:
        """校验访问令牌并确认其会话仍然存活，返回令牌声明。

        会话一旦被撤销（登出/按会话撤销/超额驱逐/重放吊销），
        该会话签发的访问令牌在此立即被拒，不等自然过期。
        """
        now = self.now() if now is None else now
        cfg = self.config
        logger.info("authenticate input: header_present=%s now=%.3f",
                    authorization_header is not None, now)

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
                logger.info("authenticate decision: RATE_LIMITED_ACCESS subject=%s", claims.sub)
                raise AccessRateLimitedError()

            # 会话状态与判定在同一 store 临界区内读取：
            # 与撤销操作串行化，撤销生效后此处必见 revoked/缺失
            session = self.store.db.sessions.get(claims.session_id)
            if session is None or session.revoked or now >= session.expires_at:
                reason = ("session removed" if session is None
                          else session.revoke_reason or "session expired")
                err = SessionRevokedError(f"session={claims.session_id} reason={reason}")
                self._access_failure(claims.sub, err, now)
                raise err

            logger.info("authenticate decision: OK subject=%s session=%s jti=%s",
                        claims.sub, claims.session_id, claims.jti)
            return claims

    def authorize(self, authorization_header: str | None, required_scope: str,
                  now: float | None = None) -> str:
        now = self.now() if now is None else now
        logger.info("authorize input: header_present=%s required_scope=%s now=%.3f",
                    authorization_header is not None, required_scope, now)
        claims = self.authenticate(authorization_header, now)

        with self.store:
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

    # ------------------------------------------------------------------
    # 会话管理：列表 / 登出 / 按会话撤销 / 撤销其它会话
    # ------------------------------------------------------------------
    def list_sessions(self, authorization_header: str | None,
                      now: float | None = None) -> list[SessionInfo]:
        """列出当前用户名下所有存活会话；只含本人会话，不暴露任何他人信息。"""
        now = self.now() if now is None else now
        claims = self.authenticate(authorization_header, now)
        with self.store:
            infos = [
                SessionInfo(
                    session_id=s.session_id,
                    client_label=s.client_label,
                    created_at=s.created_at,
                    last_refresh_at=s.last_refresh_at,
                    is_current=s.session_id == claims.session_id,
                )
                for s in self._alive_sessions(claims.sub, now)
            ]
            infos.sort(key=lambda i: (i.created_at, i.session_id))
            logger.info("sessions list: subject=%s count=%d current=%s",
                        claims.sub, len(infos), claims.session_id)
            return infos

    def logout(self, authorization_header: str | None,
               now: float | None = None) -> str:
        """登出当前会话：撤销本请求所在的会话，返回其 session_id。"""
        now = self.now() if now is None else now
        claims = self.authenticate(authorization_header, now)
        with self.store:
            session = self.store.db.sessions.get(claims.session_id)
            if session is not None:
                self._revoke_session_record(session, reason="user_logout")
            logger.info("logout decision: REVOKED subject=%s session=%s",
                        claims.sub, claims.session_id)
            return claims.session_id

    def revoke_session(self, authorization_header: str | None, session_id: str,
                       now: float | None = None) -> bool:
        """按 id 撤销自己的一条会话；幂等。

        目标不属于当前用户或不存在时不做任何变更，对外表现与成功一致，
        不泄露目标会话/用户是否存在。返回本次是否实际撤销了自有会话（仅日志用）。
        """
        now = self.now() if now is None else now
        claims = self.authenticate(authorization_header, now)
        with self.store:
            session = self.store.db.sessions.get(session_id)
            acted = (
                session is not None
                and session.username == claims.sub
                and not session.revoked
            )
            if acted:
                self._revoke_session_record(session, reason="user_revoke")
            logger.info("revoke decision: subject=%s target=%s acted=%s "
                        "(foreign/missing targets are indistinguishable)",
                        claims.sub, session_id, acted)
            return acted

    def revoke_other_sessions(self, authorization_header: str | None,
                              now: float | None = None) -> list[str]:
        """撤销当前用户除本请求所在会话以外的全部会话；幂等。返回被撤销的 id。"""
        now = self.now() if now is None else now
        claims = self.authenticate(authorization_header, now)
        with self.store:
            revoked = []
            for s in self.store.db.sessions.values():
                if (s.username == claims.sub
                        and s.session_id != claims.session_id
                        and not s.revoked):
                    self._revoke_session_record(s, reason="user_revoke_others")
                    revoked.append(s.session_id)
            revoked.sort()
            logger.info("revoke-others decision: subject=%s keep=%s revoked=%s",
                        claims.sub, claims.session_id, revoked)
            return revoked

    # ------------------------------------------------------------------
    # 清理：移除已撤销/已过期的会话与过期刷新令牌记录，防止无限堆积
    # ------------------------------------------------------------------
    def cleanup(self, now: float | None = None) -> dict[str, int]:
        """清理死状态；存活（未撤销且未过期）的会话与其令牌记录绝不受影响。

        - 会话：已撤销 或 已过期 -> 移除（被移除后刷新/访问仍被确定性地拒绝）；
        - 刷新令牌记录：过期 -> 移除（未过期的已消费记录保留，用于重放检测）。
        状态随 store 临界区落盘，清理与重启后判定保持一致。
        """
        now = self.now() if now is None else now
        with self.store:
            db = self.store.db
            dead_sessions = sorted(
                sid for sid, s in db.sessions.items()
                if s.revoked or now >= s.expires_at
            )
            for sid in dead_sessions:
                del db.sessions[sid]
            dead_tokens = sorted(
                jti for jti, r in db.refresh_tokens.items()
                if now >= r.expires_at
            )
            for jti in dead_tokens:
                del db.refresh_tokens[jti]
            logger.info("cleanup decision: now=%.3f sessions_removed=%d tokens_removed=%d "
                        "sessions_left=%d tokens_left=%d",
                        now, len(dead_sessions), len(dead_tokens),
                        len(db.sessions), len(db.refresh_tokens))
            return {
                "sessions_removed": len(dead_sessions),
                "refresh_tokens_removed": len(dead_tokens),
            }
