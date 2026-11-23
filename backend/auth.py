"""
Enterprise Authentication, Password Hashing (PBKDF2-HMAC-SHA256), Session Management,
Rate Limiting, Audit Logging, and Fine-Grained Document/Graph Authorization.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import HTTPException, status

from backend.config import Principal, settings
from backend.database import get_db_connection

logger = logging.getLogger("automated_graphrag.auth")

PBKDF2_ITERATIONS = 310_000
SESSION_COOKIE_NAME = "graphrag_session"
CSRF_HEADER_NAME = "X-CSRF-Token"

MAX_LOGIN_ATTEMPTS_WINDOW = 5
LOGIN_WINDOW_SECONDS = 600.0  # 10 minutes
_DEV_FALLBACK_WARNED = False


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def hash_password(password: str) -> str:
    """Hash a plaintext password using PBKDF2-HMAC-SHA256 with a 16-byte cryptographic salt."""
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored PBKDF2-HMAC-SHA256 hash in constant time."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_dk = bytes.fromhex(parts[3])
        candidate_dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(candidate_dk, expected_dk)
    except Exception:
        return False


def hash_session_token(raw_token: str) -> str:
    """Hash raw session token before storing or looking up in the database."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def get_session_signing_secret() -> bytes:
    """
    Resolve cryptographic key for signing session tokens.
    - Production (`APP_ENV=production`): fails closed unless SESSION_SECRET (>= 32 chars) is set.
    - Development / Test: uses SESSION_SECRET if configured, else deterministic dev key with warning.
    """
    global _DEV_FALLBACK_WARNED
    explicit = (
        settings.session_secret
        or os.environ.get("SESSION_SECRET")
        or os.environ.get("SECRET_KEY")
        or ""
    ).strip()

    if settings.is_production:
        if len(explicit) < 32:
            raise RuntimeError(
                "SESSION_SECRET (>= 32 characters) is mandatory when APP_ENV=production."
            )
        return explicit.encode("utf-8")

    if explicit:
        return explicit.encode("utf-8")

    if not _DEV_FALLBACK_WARNED:
        logger.warning(
            "SESSION_SECRET not set in %s mode; using deterministic dev signing key (forbidden in production).",
            settings.app_env,
        )
        _DEV_FALLBACK_WARNED = True

    seed = f"{settings.initial_admin_password}::{settings.initial_admin_email}::{settings.initial_admin_tenant}::graphrag-dev-v1"
    return hashlib.sha256(seed.encode("utf-8")).digest()


def create_signed_session_token(
    user_row: sqlite3.Row | Dict[str, Any],
    csrf_token: str,
    expires_iso: str,
) -> str:
    """
    Generate a self-contained, tamper-evident HMAC-SHA256 signed session token.
    Format: v1.<base64url_json_payload>.<hmac_sha256_hex>
    Includes `tv` (token_version) so revocations and password resets invalidate
    previously issued tokens immediately against the database.
    """
    secret = get_session_signing_secret()
    row_dict = dict(user_row)
    payload: Dict[str, Any] = {
        "uid": row_dict["user_id"],
        "tid": row_dict["tenant_id"],
        "usr": row_dict["username"],
        "eml": row_dict["email"],
        "fn": row_dict.get("full_name") or "",
        "rol": row_dict["role"],
        "act": int(row_dict.get("is_active", 1)),
        "tv": int(row_dict.get("token_version", 1)),
        "csrf": csrf_token,
        "exp": expires_iso,
        "rnd": secrets.token_hex(8),
    }
    raw_docs = row_dict.get("allowed_doc_ids_json")
    if raw_docs:
        payload["docs"] = raw_docs
    elif row_dict.get("allowed_doc_ids") is not None:
        payload["docs"] = json.dumps(row_dict["allowed_doc_ids"])

    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    b64_payload = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")
    sig = hmac.new(secret, b64_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"v1.{b64_payload}.{sig}"


def verify_signed_session_token(raw_token: str) -> Optional[Dict[str, Any]]:
    """
    Verify HMAC-SHA256 signature and expiration timestamp of a signed session token.
    Returns decoded payload dict if valid, or None if invalid or expired.
    """
    if not raw_token or not raw_token.startswith("v1."):
        return None

    parts = raw_token.split(".")
    if len(parts) != 3 or parts[0] != "v1":
        return None

    b64_payload, expected_sig = parts[1], parts[2]
    secret = get_session_signing_secret()
    computed_sig = hmac.new(secret, b64_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(computed_sig, expected_sig):
        return None

    try:
        padding = "=" * ((4 - len(b64_payload) % 4) % 4)
        payload_bytes = base64.urlsafe_b64decode(b64_payload + padding)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return None

    now_iso = utc_now_iso()
    if str(payload.get("exp", "")) <= now_iso:
        return None

    return payload


class RateLimiterStore(ABC):
    """Abstract sliding-window rate limiter store (supports DB and Redis adapters)."""

    @abstractmethod
    def check_and_prune(self, bucket_keys: Tuple[str, ...], window_seconds: float, max_attempts: int, db_path: Optional[str] = None) -> None:
        raise NotImplementedError

    @abstractmethod
    def record_failure(self, bucket_keys: Tuple[str, ...], db_path: Optional[str] = None) -> None:
        raise NotImplementedError

    @abstractmethod
    def clear_keys(self, bucket_keys: Tuple[str, ...], db_path: Optional[str] = None) -> None:
        raise NotImplementedError

    @abstractmethod
    def reset_all(self, db_path: Optional[str] = None) -> None:
        raise NotImplementedError


class DatabaseRateLimiterStore(RateLimiterStore):
    """Transactional SQLite/shared-DB sliding-window login rate limiter."""

    def _ensure_schema(self, db_path: Optional[str] = None) -> None:
        from backend.database import init_db
        init_db(db_path)

    def check_and_prune(
        self,
        bucket_keys: Tuple[str, ...],
        window_seconds: float,
        max_attempts: int,
        db_path: Optional[str] = None,
    ) -> None:
        cutoff = time.time() - window_seconds
        try:
            with get_db_connection(db_path) as conn:
                conn.execute("DELETE FROM login_rate_limits WHERE attempt_ts <= ?", (cutoff,))
                for key in bucket_keys:
                    cnt = conn.execute(
                        "SELECT COUNT(*) AS c FROM login_rate_limits WHERE bucket_key = ? AND attempt_ts > ?",
                        (key, cutoff),
                    ).fetchone()["c"]
                    if int(cnt) >= max_attempts:
                        raise HTTPException(
                            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many failed login attempts. Please wait 10 minutes before trying again.",
                        )
        except sqlite3.OperationalError:
            self._ensure_schema(db_path)

    def record_failure(self, bucket_keys: Tuple[str, ...], db_path: Optional[str] = None) -> None:
        now_ts = time.time()
        rows = [(key, now_ts) for key in bucket_keys]
        try:
            with get_db_connection(db_path) as conn:
                conn.executemany(
                    "INSERT INTO login_rate_limits (bucket_key, attempt_ts) VALUES (?, ?)",
                    rows,
                )
        except sqlite3.OperationalError:
            self._ensure_schema(db_path)
            with get_db_connection(db_path) as conn:
                conn.executemany(
                    "INSERT INTO login_rate_limits (bucket_key, attempt_ts) VALUES (?, ?)",
                    rows,
                )

    def clear_keys(self, bucket_keys: Tuple[str, ...], db_path: Optional[str] = None) -> None:
        if not bucket_keys:
            return
        try:
            with get_db_connection(db_path) as conn:
                placeholders = ",".join("?" for _ in bucket_keys)
                conn.execute(
                    f"DELETE FROM login_rate_limits WHERE bucket_key IN ({placeholders})",
                    tuple(bucket_keys),
                )
        except sqlite3.OperationalError:
            pass

    def reset_all(self, db_path: Optional[str] = None) -> None:
        try:
            with get_db_connection(db_path) as conn:
                conn.execute("DELETE FROM login_rate_limits")
        except sqlite3.OperationalError:
            pass


_RATE_LIMITER: RateLimiterStore = DatabaseRateLimiterStore()


def check_login_rate_limit(ip_addr: str, identifier: str, db_path: Optional[str] = None) -> None:
    """Enforce persistent sliding-window login throttling per IP and account identifier."""
    keys = (f"ip:{ip_addr}", f"acct:{identifier.lower().strip()}")
    _RATE_LIMITER.check_and_prune(keys, LOGIN_WINDOW_SECONDS, MAX_LOGIN_ATTEMPTS_WINDOW, db_path=db_path)


def record_failed_login_attempt(ip_addr: str, identifier: str, db_path: Optional[str] = None) -> None:
    """Persist a failed login timestamp for sliding-window rate limiting."""
    keys = (f"ip:{ip_addr}", f"acct:{identifier.lower().strip()}")
    _RATE_LIMITER.record_failure(keys, db_path=db_path)


def clear_login_rate_limit(ip_addr: str, identifier: str, db_path: Optional[str] = None) -> None:
    """Clear failed login counters for an account upon successful authentication."""
    _RATE_LIMITER.clear_keys((f"acct:{identifier.lower().strip()}",), db_path=db_path)


def reset_rate_limiter_state(db_path: Optional[str] = None) -> None:
    """Clear rate limit state (used in test fixtures)."""
    _RATE_LIMITER.reset_all(db_path=db_path)


def record_audit_event(
    tenant_id: str,
    actor_user_id: str,
    actor_role: str,
    action: str,
    target_type: str,
    target_id: Optional[str] = "system",
    outcome: Optional[str] = None,
    status: Optional[str] = None,
    actor_username: Optional[str] = None,
    ip_address: str = "127.0.0.1",
    details: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None,
) -> None:
    """Persist a tamper-evident security audit log entry without sensitive secrets."""
    now = utc_now_iso()
    final_outcome = outcome or status or "success"
    final_target_id = target_id or "system"
    raw = f"{tenant_id}::{actor_user_id}::{action}::{final_target_id}::{now}::{secrets.token_hex(4)}"
    audit_id = "aud-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:14]

    safe_details: Dict[str, Any] = {}
    if actor_username:
        safe_details["actor_username"] = actor_username
    if details:
        for k, v in details.items():
            if any(sec in k.lower() for sec in ("password", "secret", "token", "api_key")):
                continue
            safe_details[k] = v

    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (
                audit_id, tenant_id, actor_user_id, actor_role, action,
                target_type, target_id, outcome, ip_address, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                tenant_id,
                actor_user_id,
                actor_role,
                action,
                target_type,
                final_target_id,
                final_outcome,
                ip_address,
                json.dumps(safe_details),
                now,
            ),
        )


def seed_default_users(db_path: Optional[str] = None) -> None:
    """
    Idempotently provision initial administrator and standard role accounts if the `users`
    table is empty. Reads initial credentials from environment settings (`INITIAL_ADMIN_*`)
    so production deployments never rely on undocumented hardcoded credentials.
    """
    now = utc_now_iso()
    with get_db_connection(db_path) as conn:
        existing_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if int(existing_count) > 0:
            return

        bootstrap_accounts = [
            {
                "user_id": "user-admin",
                "tenant_id": settings.initial_admin_tenant,
                "username": settings.initial_admin_username,
                "email": settings.initial_admin_email,
                "full_name": "Elena Vance (Platform Admin)",
                "password": settings.initial_admin_password,
                "role": "admin",
                "is_active": 1,
                "allowed_doc_ids": ["*"],
            },
            {
                "user_id": "user-analyst",
                "tenant_id": settings.initial_admin_tenant,
                "username": "analyst",
                "email": "analyst@aurelia-cloud.internal",
                "full_name": "Marcus Sterling (Risk Analyst)",
                "password": settings.initial_analyst_password,
                "role": "analyst",
                "is_active": 1,
                "allowed_doc_ids": ["*"],
            },
            {
                "user_id": "user-viewer",
                "tenant_id": settings.initial_admin_tenant,
                "username": "viewer",
                "email": "viewer@aurelia-cloud.internal",
                "full_name": "Clara Chen (Audit Viewer)",
                "password": settings.initial_viewer_password,
                "role": "viewer",
                "is_active": 1,
                "allowed_doc_ids": ["*"],
            },
            {
                "user_id": "user-beta",
                "tenant_id": "tenant-beta",
                "username": "beta_analyst",
                "email": "analyst@beta-holdings.internal",
                "full_name": "David Thorne (Tenant Beta Analyst)",
                "password": settings.initial_analyst_password,
                "role": "analyst",
                "is_active": 1,
                "allowed_doc_ids": ["*"],
            },
        ]

        for acct in bootstrap_accounts:
            pw_hash = hash_password(str(acct["password"]))
            conn.execute(
                """
                INSERT OR IGNORE INTO users (
                    user_id, tenant_id, username, email, full_name,
                    password_hash, role, is_active, allowed_doc_ids_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    acct["user_id"],
                    acct["tenant_id"],
                    str(acct["username"]).lower().strip(),
                    str(acct["email"]).lower().strip(),
                    acct["full_name"],
                    pw_hash,
                    acct["role"],
                    acct["is_active"],
                    json.dumps(acct["allowed_doc_ids"]),
                    now,
                    now,
                ),
            )


def authenticate_user_credentials(
    identifier: str,
    password: str,
    ip_address: str = "127.0.0.1",
    user_agent: str = "",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verify username or email + password, create a new server-side session,
    and return session tokens + sanitized user dictionary.
    Never reveals whether a specific username/email exists on failure.
    """
    clean_id = identifier.strip().lower()
    check_login_rate_limit(ip_address, clean_id, db_path=db_path)

    with get_db_connection(db_path) as conn:
        user_row = conn.execute(
            """
            SELECT user_id, tenant_id, username, email, full_name,
                   password_hash, role, is_active, allowed_doc_ids_json,
                   token_version, created_at, updated_at, last_login_at
            FROM users
            WHERE lower(username) = ? OR lower(email) = ?
            LIMIT 1
            """,
            (clean_id, clean_id),
        ).fetchone()

    # Constant-time dummy check if user does not exist to prevent timing enumeration
    if not user_row:
        verify_password(password, hash_password("dummy-comparison-password-value"))
        record_failed_login_attempt(ip_address, clean_id, db_path=db_path)
        record_audit_event(
            tenant_id="system",
            actor_user_id="anonymous",
            actor_role="unauthenticated",
            action="auth.login",
            target_type="user",
            target_id=clean_id,
            outcome="failure",
            ip_address=ip_address,
            details={"reason": "invalid_credentials"},
            db_path=db_path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password.",
        )

    if not verify_password(password, user_row["password_hash"]):
        record_failed_login_attempt(ip_address, clean_id, db_path=db_path)
        record_audit_event(
            tenant_id=user_row["tenant_id"],
            actor_user_id=user_row["user_id"],
            actor_role=user_row["role"],
            action="auth.login",
            target_type="user",
            target_id=user_row["user_id"],
            outcome="failure",
            ip_address=ip_address,
            details={"reason": "invalid_password"},
            db_path=db_path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password.",
        )

    if int(user_row["is_active"]) == 0:
        record_audit_event(
            tenant_id=user_row["tenant_id"],
            actor_user_id=user_row["user_id"],
            actor_role=user_row["role"],
            action="auth.login",
            target_type="user",
            target_id=user_row["user_id"],
            outcome="denied",
            ip_address=ip_address,
            details={"reason": "account_deactivated"},
            db_path=db_path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password.",
        )

    clear_login_rate_limit(ip_address, clean_id, db_path=db_path)

    # Generate fresh signed session token and CSRF token (prevents session fixation and supports serverless multi-container dispatch)
    csrf_token = secrets.token_urlsafe(24)
    now = utc_now()
    now_iso = now.isoformat()
    expires_iso = (now + timedelta(minutes=settings.session_ttl_minutes)).isoformat()
    raw_session_token = create_signed_session_token(user_row, csrf_token, expires_iso)
    session_id = hash_session_token(raw_session_token)

    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO user_sessions (
                session_id, user_id, tenant_id, csrf_token,
                ip_address, user_agent, created_at, expires_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                session_id,
                user_row["user_id"],
                user_row["tenant_id"],
                csrf_token,
                ip_address,
                user_agent[:250],
                now_iso,
                expires_iso,
            ),
        )
        conn.execute(
            "UPDATE users SET last_login_at = ?, updated_at = ? WHERE user_id = ?",
            (now_iso, now_iso, user_row["user_id"]),
        )

    record_audit_event(
        tenant_id=user_row["tenant_id"],
        actor_user_id=user_row["user_id"],
        actor_role=user_row["role"],
        action="auth.login",
        target_type="session",
        target_id=session_id[:12],
        outcome="success",
        ip_address=ip_address,
        db_path=db_path,
    )

    return {
        "session_token": raw_session_token,
        "csrf_token": csrf_token,
        "expires_at": expires_iso,
        "user": format_sanitized_user(user_row),
    }


def resolve_session_principal(
    raw_token: str,
    require_csrf: bool = False,
    provided_csrf: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Principal:
    """Validate an active session token against `user_sessions`, `users.token_version`, and HMAC signature."""
    session_id = hash_session_token(raw_token)
    now_iso = utc_now_iso()
    signed_payload = verify_signed_session_token(raw_token) if raw_token.startswith("v1.") else None

    if raw_token.startswith("v1.") and signed_payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session. Please sign in again.",
        )

    try:
        with get_db_connection(db_path) as conn:
            row = conn.execute(
                """
                SELECT s.session_id, s.csrf_token, s.expires_at, s.revoked_at,
                       u.user_id, u.tenant_id, u.username, u.email, u.full_name,
                       u.role, u.is_active, u.allowed_doc_ids_json, u.token_version
                FROM user_sessions s
                JOIN users u ON u.user_id = s.user_id
                WHERE s.session_id = ?
                """,
                (session_id,),
            ).fetchone()
    except sqlite3.OperationalError:
        from backend.database import init_db
        init_db(db_path)
        with get_db_connection(db_path) as conn:
            row = conn.execute(
                """
                SELECT s.session_id, s.csrf_token, s.expires_at, s.revoked_at,
                       u.user_id, u.tenant_id, u.username, u.email, u.full_name,
                       u.role, u.is_active, u.allowed_doc_ids_json, u.token_version
                FROM user_sessions s
                JOIN users u ON u.user_id = s.user_id
                WHERE s.session_id = ?
                """,
                (session_id,),
            ).fetchone()

    # If session not in this container's DB, check if it's a valid signed token
    if not row:
        payload = signed_payload
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session. Please sign in again.",
            )

        with get_db_connection(db_path) as conn:
            # Check if session was explicitly revoked in this DB
            revoked_row = conn.execute(
                "SELECT revoked_at FROM user_sessions WHERE session_id = ? AND revoked_at IS NOT NULL",
                (session_id,),
            ).fetchone()
            if revoked_row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session has been revoked. Please sign in again.",
                )

            # Check if user exists in local DB
            u_row = conn.execute(
                "SELECT user_id, tenant_id, username, email, full_name, role, is_active, allowed_doc_ids_json, token_version FROM users WHERE user_id = ?",
                (payload["uid"],),
            ).fetchone()

            if not u_row:
                seed_default_users(db_path)
                u_row = conn.execute(
                    "SELECT user_id, tenant_id, username, email, full_name, role, is_active, allowed_doc_ids_json, token_version FROM users WHERE user_id = ?",
                    (payload["uid"],),
                ).fetchone()

            if u_row:
                # Validate token_version BEFORE provisioning session row
                if int(payload.get("tv", 1)) != int(u_row["token_version"]):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session has been revoked. Please sign in again.",
                    )
                if int(u_row["is_active"]) == 0:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="User account is deactivated.",
                    )
            else:
                # Serverless fallback: provision account from verified signed token payload
                conn.execute(
                    """
                    INSERT OR IGNORE INTO users (
                        user_id, tenant_id, username, email, full_name,
                        password_hash, role, is_active, allowed_doc_ids_json,
                        token_version, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["uid"],
                        payload["tid"],
                        payload["usr"],
                        payload["eml"],
                        payload.get("fn", ""),
                        hash_password("serverless-sync-" + secrets.token_hex(8)),
                        payload["rol"],
                        payload.get("act", 1),
                        payload.get("docs", '["*"]'),
                        int(payload.get("tv", 1)),
                        now_iso,
                        now_iso,
                    ),
                )

            # Record session into local container DB so subsequent queries in this container find it
            conn.execute(
                """
                INSERT OR IGNORE INTO user_sessions (
                    session_id, user_id, tenant_id, csrf_token,
                    ip_address, user_agent, created_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    session_id,
                    payload["uid"],
                    payload["tid"],
                    payload["csrf"],
                    "serverless-sync",
                    "sync",
                    now_iso,
                    payload["exp"],
                ),
            )

            row = conn.execute(
                """
                SELECT s.session_id, s.csrf_token, s.expires_at, s.revoked_at,
                       u.user_id, u.tenant_id, u.username, u.email, u.full_name,
                       u.role, u.is_active, u.allowed_doc_ids_json, u.token_version
                FROM user_sessions s
                JOIN users u ON u.user_id = s.user_id
                WHERE s.session_id = ?
                """,
                (session_id,),
            ).fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session. Please sign in again.",
        )

    if row["revoked_at"] is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked. Please sign in again.",
        )

    if signed_payload is not None and int(signed_payload.get("tv", 1)) != int(row["token_version"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked. Please sign in again.",
        )

    if str(row["expires_at"]) <= now_iso:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired. Please sign in again.",
        )

    if int(row["is_active"]) == 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    if require_csrf:
        if not provided_csrf or not hmac.compare_digest(str(row["csrf_token"]), provided_csrf.strip()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing or invalid CSRF token for cookie-authenticated state-changing request.",
            )

    allowed_docs = json.loads(row["allowed_doc_ids_json"] or '["*"]')
    return Principal(
        user_id=row["user_id"],
        tenant_id=row["tenant_id"],
        username=row["username"],
        email=row["email"],
        full_name=row["full_name"],
        role=row["role"],
        auth_method="session",
        allowed_doc_ids=allowed_docs,
        csrf_token=row["csrf_token"],
    )


def revoke_session_by_token(
    raw_token: str, db_path: Optional[str] = None
) -> bool:
    """Revoke a single session token. Returns True if an active session was revoked."""
    session_id = hash_session_token(raw_token)
    now_iso = utc_now_iso()
    with get_db_connection(db_path) as conn:
        cur = conn.execute(
            "UPDATE user_sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL",
            (now_iso, session_id),
        )
        return cur.rowcount > 0


def revoke_all_user_sessions(
    tenant_id: str, user_id: str, db_path: Optional[str] = None
) -> int:
    """Revoke all active sessions for a specific user and increment token_version atomically."""
    now_iso = utc_now_iso()
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            UPDATE users
            SET token_version = token_version + 1, updated_at = ?
            WHERE tenant_id = ? AND user_id = ?
            """,
            (now_iso, tenant_id, user_id),
        )
        cur = conn.execute(
            """
            UPDATE user_sessions
            SET revoked_at = ?
            WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL
            """,
            (now_iso, tenant_id, user_id),
        )
        return int(cur.rowcount)


def rotate_user_token_version_for_password_change(
    tenant_id: str,
    user_id: str,
    current_raw_token: Optional[str] = None,
    ip_address: str = "127.0.0.1",
    user_agent: str = "",
    db_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Increment `users.token_version` and revoke all prior sessions on password change.
    If the caller authenticated via an active session, issues a refreshed signed session
    with the new `token_version` (preserving its CSRF token so the active tab remains usable).
    """
    now = utc_now()
    now_iso = now.isoformat()
    preserved_csrf: Optional[str] = None
    with get_db_connection(db_path) as conn:
        if current_raw_token:
            old_sid = hash_session_token(current_raw_token)
            sess_row = conn.execute(
                """
                SELECT csrf_token FROM user_sessions
                WHERE session_id = ? AND tenant_id = ? AND user_id = ? AND revoked_at IS NULL
                """,
                (old_sid, tenant_id, user_id),
            ).fetchone()
            if sess_row:
                preserved_csrf = str(sess_row["csrf_token"])

        conn.execute(
            """
            UPDATE users
            SET token_version = token_version + 1, updated_at = ?
            WHERE tenant_id = ? AND user_id = ?
            """,
            (now_iso, tenant_id, user_id),
        )
        conn.execute(
            """
            UPDATE user_sessions
            SET revoked_at = ?
            WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL
            """,
            (now_iso, tenant_id, user_id),
        )
        user_row = conn.execute(
            """
            SELECT user_id, tenant_id, username, email, full_name,
                   role, is_active, allowed_doc_ids_json, token_version
            FROM users
            WHERE tenant_id = ? AND user_id = ?
            """,
            (tenant_id, user_id),
        ).fetchone()

        if not user_row or not preserved_csrf:
            return None

        expires_iso = (now + timedelta(minutes=settings.session_ttl_minutes)).isoformat()
        new_raw_token = create_signed_session_token(user_row, preserved_csrf, expires_iso)
        new_sid = hash_session_token(new_raw_token)
        conn.execute(
            """
            INSERT INTO user_sessions (
                session_id, user_id, tenant_id, csrf_token,
                ip_address, user_agent, created_at, expires_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                new_sid,
                user_row["user_id"],
                user_row["tenant_id"],
                preserved_csrf,
                ip_address,
                user_agent[:250],
                now_iso,
                expires_iso,
            ),
        )
        return {
            "session_token": new_raw_token,
            "csrf_token": preserved_csrf,
            "expires_at": expires_iso,
        }


def get_authorized_doc_ids_for_principal(
    principal: Principal,
    requested_doc_ids: Optional[List[str]] = None,
    db_path: Optional[str] = None,
) -> List[str]:
    """
    Compute the exact list of `doc_id`s in `principal.tenant_id` that `principal` is authorized
    to read/query.
    - Enforces tenant boundary.
    - Enforces document-level `visibility`, `allowed_roles_json`, and `allowed_user_ids_json`.
    - Enforces user-level `allowed_doc_ids` scope (when not `None` and not `["*"]`).
    """
    with get_db_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT doc_id, owner_user_id, visibility, allowed_roles_json, allowed_user_ids_json
            FROM documents
            WHERE tenant_id = ?
            """,
            (principal.tenant_id,),
        ).fetchall()

    raw_user_docs = principal.allowed_doc_ids
    if raw_user_docs is None or "*" in raw_user_docs:
        unrestricted_user_scope = True
        user_doc_scope: Set[str] = set()
    else:
        unrestricted_user_scope = False
        user_doc_scope = set(raw_user_docs)

    permitted: List[str] = []
    for r in rows:
        did = str(r["doc_id"])
        if requested_doc_ids is not None and did not in requested_doc_ids:
            continue

        # Admins have full visibility inside their own tenant
        if principal.role == "admin":
            permitted.append(did)
            continue

        # Check user-level allowed_doc_ids restriction
        if not unrestricted_user_scope and did not in user_doc_scope:
            continue

        # Check document-level visibility & role/user allowlist
        visibility = str(r["visibility"] or "tenant")
        allowed_roles = json.loads(r["allowed_roles_json"] or '["admin","analyst","viewer"]')
        allowed_users = json.loads(r["allowed_user_ids_json"] or "[]")

        if visibility == "private":
            if principal.user_id != r["owner_user_id"] and principal.user_id not in allowed_users:
                continue
        elif visibility == "restricted":
            if (
                principal.user_id != r["owner_user_id"]
                and principal.user_id not in allowed_users
                and principal.role not in allowed_roles
            ):
                continue
        else:
            if principal.role not in allowed_roles and principal.user_id not in allowed_users:
                continue

        permitted.append(did)

    return permitted


def format_sanitized_user(row: sqlite3.Row | Dict[str, Any]) -> Dict[str, Any]:
    """Serialize a user row without ever exposing `password_hash`."""
    d = dict(row)
    raw_docs_json = d.get("allowed_doc_ids_json")
    parsed_docs: Optional[List[str]] = None
    if raw_docs_json:
        try:
            loaded = json.loads(raw_docs_json)
            if isinstance(loaded, list) and "*" not in loaded:
                parsed_docs = [str(x) for x in loaded]
        except Exception:
            parsed_docs = None

    return {
        "user_id": d["user_id"],
        "tenant_id": d["tenant_id"],
        "username": d["username"],
        "email": d["email"],
        "full_name": d.get("full_name", ""),
        "role": d["role"],
        "is_active": bool(d.get("is_active", 1)),
        "allowed_doc_ids": parsed_docs,
        "created_at": d.get("created_at"),
        "updated_at": d.get("updated_at"),
        "last_login_at": d.get("last_login_at"),
    }
