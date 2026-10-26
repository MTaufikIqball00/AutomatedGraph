"""FastAPI application entry point for Automated GraphRAG."""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.auth import (
    SESSION_COOKIE_NAME,
    authenticate_user_credentials,
    format_sanitized_user,
    get_authorized_doc_ids_for_principal,
    hash_password,
    record_audit_event,
    revoke_all_user_sessions,
    revoke_session_by_token,
    verify_password,
)
from backend.config import ROLE_PERMISSION_MATRIX, Principal, settings
from backend.database import get_db_connection, init_db
from backend.demo_fixtures import SYNTHETIC_DEMO_DOCUMENTS
from backend.evaluation import run_comparative_evaluation
from backend.generation import synthesize_grounded_answer
from backend.graph_store import KnowledgeGraphStore, utc_now_iso
from backend.pipeline import ingest_and_index_document
from backend.retrieval import execute_hybrid_retrieval
from backend.schemas import (
    ConfigUpdateRequest,
    DocumentACLUpdateRequest,
    DocumentSummary,
    LoginRequest,
    PasswordChangeRequest,
    QueryRequest,
    QueryResponse,
    UserCreateRequest,
    UserUpdateRequest,
)
from backend.security import (
    CypherGuard,
    require_permission,
    require_role,
    resolve_principal,
    validate_upload_file,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("automated_graphrag")


@asynccontextmanager
async def lifespan(app: FastAPI) -> Iterator[None]:
    """Initialize SQLite schema and bootstrap default users on startup."""
    init_db()
    logger.info("Automated GraphRAG database schema initialized at %s", settings.sqlite_db_path)
    yield


app = FastAPI(
    title="Automated GraphRAG Enterprise API",
    version="1.1.0",
    description=(
        "Production-oriented Automated GraphRAG system with structure-aware ingestion, "
        "schema-validated extraction, entity resolution, provenance-backed knowledge graph, "
        "hybrid retrieval, evidence-grounded synthesis, and RBAC + Document ACL security."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _client_ip(request: Request) -> str:
    """Resolve caller IP address safely for rate limiting and audit logging."""
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


@app.get("/api/health")
def health_check() -> Dict[str, Any]:
    """System health check without leaking secrets."""
    init_db()
    with get_db_connection() as conn:
        doc_count = conn.execute("SELECT COUNT(*) AS c FROM documents").fetchone()["c"]
    return {
        "status": "healthy",
        "version": "1.1.0",
        "graph_backend": settings.graph_backend,
        "llm_provider": settings.llm_provider,
        "embedding_provider": settings.embedding_provider,
        "total_documents_all_tenants": int(doc_count),
        "timestamp": utc_now_iso(),
    }


# ==============================================================================
# AUTHENTICATION & SESSION MANAGEMENT ENDPOINTS
# ==============================================================================


@app.post("/api/auth/login")
def login_endpoint(
    req: LoginRequest,
    request: Request,
    response: Response,
) -> Dict[str, Any]:
    """
    Authenticate user with username/email and password.
    Sets an HttpOnly, SameSite=Lax session cookie and returns CSRF token + user profile.
    """
    init_db()
    ip_addr = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    auth_result = authenticate_user_credentials(
        identifier=req.identifier,
        password=req.password,
        ip_address=ip_addr,
        user_agent=user_agent,
    )

    max_age_seconds = max(300, settings.session_ttl_minutes * 60)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=auth_result["session_token"],
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=max_age_seconds,
        path="/",
    )

    user_dict = auth_result["user"]
    role = user_dict.get("role", "viewer")
    return {
        "status": "authenticated",
        "user": user_dict,
        "csrf_token": auth_result["csrf_token"],
        "session_token": auth_result["session_token"],
        "expires_at": auth_result["expires_at"],
        "permissions": ROLE_PERMISSION_MATRIX.get(role, []),
    }


@app.post("/api/auth/logout")
def logout_endpoint(
    request: Request,
    response: Response,
    session_cookie: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Revoke the caller's active server-side session and clear session cookie."""
    token_to_revoke: Optional[str] = session_cookie
    if not token_to_revoke and authorization and authorization.lower().startswith("bearer "):
        token_to_revoke = authorization[7:].strip()

    revoked = False
    if token_to_revoke:
        revoked = revoke_session_by_token(token_to_revoke)

    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    record_audit_event(
        tenant_id=principal.tenant_id,
        actor_user_id=principal.user_id,
        actor_username=principal.username,
        actor_role=principal.role,
        action="auth.logout",
        target_type="session",
        target_id=principal.user_id,
        status="success",
        ip_address=_client_ip(request),
        details={"session_revoked": revoked},
    )
    return {"status": "logged_out", "session_revoked": revoked}


@app.post("/api/auth/change-password")
def change_password_endpoint(
    req: PasswordChangeRequest,
    request: Request,
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Verify current password, update to a new hashed password, and log audit event."""
    if req.current_password == req.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from your current password.",
        )

    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT user_id, password_hash FROM users WHERE tenant_id = ? AND user_id = ?",
            (principal.tenant_id, principal.user_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User account record not found.")

        if not verify_password(req.current_password, row["password_hash"]):
            record_audit_event(
                tenant_id=principal.tenant_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                actor_role=principal.role,
                action="auth.change_password",
                target_type="user",
                target_id=principal.user_id,
                status="denied",
                ip_address=_client_ip(request),
                details={"reason": "incorrect_current_password"},
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password verification failed.",
            )

        new_hash = hash_password(req.new_password)
        conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE tenant_id = ? AND user_id = ?",
            (new_hash, utc_now_iso(), principal.tenant_id, principal.user_id),
        )

    record_audit_event(
        tenant_id=principal.tenant_id,
        actor_user_id=principal.user_id,
        actor_username=principal.username,
        actor_role=principal.role,
        action="auth.change_password",
        target_type="user",
        target_id=principal.user_id,
        status="success",
        ip_address=_client_ip(request),
    )
    return {"status": "password_updated"}


@app.get("/api/auth/whoami")
def whoami(principal: Principal = Depends(resolve_principal)) -> Dict[str, Any]:
    """Return caller's verified principal identity, role, and permission set."""
    data = principal.model_dump()
    data["permissions"] = ROLE_PERMISSION_MATRIX.get(principal.role, [])
    data["role_permission_matrix"] = ROLE_PERMISSION_MATRIX
    return data


@app.get("/api/auth/permissions")
def get_permission_matrix(
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Return the documented RBAC permission matrix and the caller's active permissions."""
    return {
        "caller_role": principal.role,
        "caller_permissions": ROLE_PERMISSION_MATRIX.get(principal.role, []),
        "matrix": ROLE_PERMISSION_MATRIX,
    }


# ==============================================================================
# USER MANAGEMENT & AUDIT LOG ENDPOINTS (ADMIN ONLY)
# ==============================================================================


@app.get("/api/users")
def list_users(
    search: Optional[str] = Query(default=None, max_length=120),
    role: Optional[str] = Query(default=None),
    is_active: Optional[bool] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """List users in the admin's tenant with search, filtering, and pagination."""
    require_permission(principal, "users:read")
    t_id = principal.tenant_id

    clauses = ["tenant_id = ?"]
    params: List[Any] = [t_id]

    if search and search.strip():
        q = f"%{search.strip().lower()}%"
        clauses.append("(LOWER(username) LIKE ? OR LOWER(email) LIKE ? OR LOWER(full_name) LIKE ?)")
        params.extend([q, q, q])

    if role and role in ("admin", "analyst", "viewer"):
        clauses.append("role = ?")
        params.append(role)

    if is_active is not None:
        clauses.append("is_active = ?")
        params.append(1 if is_active else 0)

    where_sql = " AND ".join(clauses)
    offset = (page - 1) * page_size
    now_iso = utc_now_iso()

    with get_db_connection() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM users WHERE {where_sql}",
            tuple(params),
        ).fetchone()["c"]

        rows = conn.execute(
            f"""
            SELECT user_id, tenant_id, username, email, full_name, role,
                   is_active, allowed_doc_ids_json, created_at, updated_at, last_login_at
            FROM users
            WHERE {where_sql}
            ORDER BY created_at ASC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [page_size, offset]),
        ).fetchall()

        users_out: List[Dict[str, Any]] = []
        for r in rows:
            u = format_sanitized_user(r)
            active_sess = conn.execute(
                """
                SELECT COUNT(*) AS c FROM user_sessions
                WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
                """,
                (u["user_id"], now_iso),
            ).fetchone()["c"]
            u["active_sessions"] = int(active_sess)
            users_out.append(u)

    return {
        "items": users_out,
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (int(total) + page_size - 1) // page_size),
    }


@app.post("/api/users", status_code=status.HTTP_201_CREATED)
def create_user(
    req: UserCreateRequest,
    request: Request,
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Create a new user account within the administrator's tenant."""
    require_permission(principal, "users:manage")
    t_id = principal.tenant_id
    username_clean = req.username.strip().lower()
    email_clean = req.email.strip().lower()

    if "@" not in email_clean or "." not in email_clean.split("@")[-1]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Please provide a valid email address.",
        )

    now = utc_now_iso()
    user_id = f"user-{secrets.token_hex(6)}"
    pw_hash = hash_password(req.password)
    allowed_docs_json = (
        json.dumps(req.allowed_doc_ids) if req.allowed_doc_ids is not None else '["*"]'
    )

    with get_db_connection() as conn:
        existing = conn.execute(
            "SELECT user_id, username, email FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?",
            (username_clean, email_clean),
        ).fetchone()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with that username or email already exists.",
            )

        conn.execute(
            """
            INSERT INTO users (
                user_id, tenant_id, username, email, full_name, password_hash,
                role, is_active, allowed_doc_ids_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                t_id,
                username_clean,
                email_clean,
                req.full_name.strip(),
                pw_hash,
                req.role,
                1 if req.is_active else 0,
                allowed_docs_json,
                now,
                now,
            ),
        )
        created_row = conn.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()

    sanitized = format_sanitized_user(created_row)
    sanitized["active_sessions"] = 0

    record_audit_event(
        tenant_id=t_id,
        actor_user_id=principal.user_id,
        actor_username=principal.username,
        actor_role=principal.role,
        action="users.create",
        target_type="user",
        target_id=user_id,
        status="success",
        ip_address=_client_ip(request),
        details={
            "created_username": username_clean,
            "role": req.role,
            "is_active": req.is_active,
            "restricted_doc_scope": req.allowed_doc_ids is not None,
        },
    )
    return sanitized


@app.patch("/api/users/{user_id}")
def update_user(
    user_id: str,
    req: UserUpdateRequest,
    request: Request,
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Update a user's profile, role, active status, document access scope, or password."""
    require_permission(principal, "users:manage")
    t_id = principal.tenant_id

    with get_db_connection() as conn:
        target = conn.execute(
            "SELECT * FROM users WHERE tenant_id = ? AND user_id = ?",
            (t_id, user_id),
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="User not found in tenant scope.")

        # Prevent self-lockout or self-demotion
        if user_id == principal.user_id:
            if req.is_active is False:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Administrators cannot deactivate their own active account.",
                )
            if req.role is not None and req.role != "admin":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Administrators cannot demote their own role.",
                )

        # Prevent removing or deactivating the last active admin in the tenant
        if target["role"] == "admin" and (
            (req.role is not None and req.role != "admin") or req.is_active is False
        ):
            other_admins = conn.execute(
                """
                SELECT COUNT(*) AS c FROM users
                WHERE tenant_id = ? AND role = 'admin' AND is_active = 1 AND user_id != ?
                """,
                (t_id, user_id),
            ).fetchone()["c"]
            if int(other_admins) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot deactivate or demote the last active administrator in the tenant.",
                )

        updates: List[str] = []
        params: List[Any] = []
        audit_changes: Dict[str, Any] = {}
        revoke_sessions_needed = False

        if req.full_name is not None:
            updates.append("full_name = ?")
            params.append(req.full_name.strip())
            audit_changes["full_name"] = req.full_name.strip()

        if req.email is not None:
            email_clean = req.email.strip().lower()
            if "@" not in email_clean:
                raise HTTPException(status_code=422, detail="Invalid email address.")
            dup = conn.execute(
                "SELECT user_id FROM users WHERE LOWER(email) = ? AND user_id != ?",
                (email_clean, user_id),
            ).fetchone()
            if dup:
                raise HTTPException(status_code=409, detail="Email is already in use by another user.")
            updates.append("email = ?")
            params.append(email_clean)
            audit_changes["email"] = email_clean

        if req.role is not None and req.role != target["role"]:
            updates.append("role = ?")
            params.append(req.role)
            audit_changes["old_role"] = target["role"]
            audit_changes["new_role"] = req.role
            revoke_sessions_needed = True

        if req.is_active is not None and bool(req.is_active) != bool(target["is_active"]):
            updates.append("is_active = ?")
            params.append(1 if req.is_active else 0)
            audit_changes["is_active"] = req.is_active
            if not req.is_active:
                revoke_sessions_needed = True

        # Check if allowed_doc_ids was explicitly provided in payload (including null to clear restriction)
        raw_fields_set = getattr(req, "model_fields_set", set())
        if "allowed_doc_ids" in raw_fields_set:
            allowed_json = (
                json.dumps(req.allowed_doc_ids) if req.allowed_doc_ids is not None else '["*"]'
            )
            updates.append("allowed_doc_ids_json = ?")
            params.append(allowed_json)
            audit_changes["allowed_doc_ids"] = req.allowed_doc_ids

        if req.new_password:
            updates.append("password_hash = ?")
            params.append(hash_password(req.new_password))
            audit_changes["password_reset_by_admin"] = True
            revoke_sessions_needed = True

        if updates:
            updates.append("updated_at = ?")
            params.append(utc_now_iso())
            params.extend([t_id, user_id])
            conn.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE tenant_id = ? AND user_id = ?",
                tuple(params),
            )

        updated_row = conn.execute(
            "SELECT * FROM users WHERE tenant_id = ? AND user_id = ?",
            (t_id, user_id),
        ).fetchone()

    revoked_count = 0
    if revoke_sessions_needed:
        revoked_count = revoke_all_user_sessions(t_id, user_id)
        audit_changes["revoked_sessions"] = revoked_count

    record_audit_event(
        tenant_id=t_id,
        actor_user_id=principal.user_id,
        actor_username=principal.username,
        actor_role=principal.role,
        action="users.update",
        target_type="user",
        target_id=user_id,
        status="success",
        ip_address=_client_ip(request),
        details=audit_changes,
    )

    sanitized = format_sanitized_user(updated_row)
    with get_db_connection() as conn:
        active_sess = conn.execute(
            """
            SELECT COUNT(*) AS c FROM user_sessions
            WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
            """,
            (user_id, utc_now_iso()),
        ).fetchone()["c"]
        sanitized["active_sessions"] = int(active_sess)
    return sanitized


@app.post("/api/users/{user_id}/revoke-sessions")
def revoke_user_sessions_endpoint(
    user_id: str,
    request: Request,
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Revoke all active sessions for a specific user in the administrator's tenant."""
    require_permission(principal, "users:manage")
    t_id = principal.tenant_id
    with get_db_connection() as conn:
        target = conn.execute(
            "SELECT user_id, username FROM users WHERE tenant_id = ? AND user_id = ?",
            (t_id, user_id),
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="User not found in tenant scope.")

    count = revoke_all_user_sessions(t_id, user_id)
    record_audit_event(
        tenant_id=t_id,
        actor_user_id=principal.user_id,
        actor_username=principal.username,
        actor_role=principal.role,
        action="users.revoke_sessions",
        target_type="user",
        target_id=user_id,
        status="success",
        ip_address=_client_ip(request),
        details={"target_username": target["username"], "revoked_count": count},
    )
    return {"status": "sessions_revoked", "user_id": user_id, "revoked_count": count}


@app.get("/api/audit-logs")
def list_audit_logs(
    action: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    search: Optional[str] = Query(default=None, max_length=120),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=30, ge=1, le=100),
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Return security and administrative audit logs for the caller's tenant (Admin only)."""
    require_permission(principal, "audit:read")
    t_id = principal.tenant_id

    clauses = ["tenant_id = ?"]
    params: List[Any] = [t_id]

    if action and action.strip():
        clauses.append("action = ?")
        params.append(action.strip())

    if status_filter and status_filter.strip():
        clauses.append("outcome = ?")
        params.append(status_filter.strip())

    if search and search.strip():
        q = f"%{search.strip().lower()}%"
        clauses.append(
            "(LOWER(actor_user_id) LIKE ? OR LOWER(action) LIKE ? OR LOWER(COALESCE(target_id, '')) LIKE ?)"
        )
        params.extend([q, q, q])

    where_sql = " AND ".join(clauses)
    offset = (page - 1) * page_size

    with get_db_connection() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM audit_logs WHERE {where_sql}",
            tuple(params),
        ).fetchone()["c"]

        rows = conn.execute(
            f"""
            SELECT audit_id, tenant_id, actor_user_id, actor_role,
                   action, target_type, target_id, outcome, ip_address, details_json, created_at
            FROM audit_logs
            WHERE {where_sql}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [page_size, offset]),
        ).fetchall()

    items: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            details = json.loads(d.pop("details_json", "{}") or "{}")
        except Exception:
            details = {}
        d["details"] = details
        d["status"] = d["outcome"]
        d["actor_username"] = details.get("actor_username") or d["actor_user_id"]
        items.append(d)

    return {
        "items": items,
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (int(total) + page_size - 1) // page_size),
    }


# ==============================================================================
# OVERVIEW, DOCUMENT INGESTION, ACL MANAGEMENT & GRAPH ENDPOINTS
# ==============================================================================


@app.get("/api/overview")
def get_overview_metrics(
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Return verified dashboard metrics scoped to the caller's tenant and authorized documents."""
    t_id = principal.tenant_id
    auth_doc_ids = get_authorized_doc_ids_for_principal(principal)

    if not auth_doc_ids:
        return {
            "tenant_id": t_id,
            "documents": {"total": 0, "completed": 0, "failed": 0, "synthetic_demo_count": 0},
            "knowledge_graph": {
                "chunks": 0,
                "entities": 0,
                "relationships": 0,
                "explicit_relationships": 0,
                "inferred_relationships": 0,
                "communities": 0,
                "uncertain_entity_matches": 0,
                "entity_types": [],
                "relationship_types": [],
            },
            "queries": {
                "total": 0,
                "avg_latency_ms": 0.0,
                "abstained": 0,
                "prompt_injections_blocked": 0,
            },
        }

    placeholders = ",".join("?" for _ in auth_doc_ids)
    doc_params: Tuple[Any, ...] = (t_id, *auth_doc_ids)

    with get_db_connection() as conn:
        doc_stats = conn.execute(
            f"""
            SELECT
                COUNT(*) AS total_docs,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_docs,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_docs,
                SUM(CASE WHEN is_synthetic_demo = 1 THEN 1 ELSE 0 END) AS demo_docs
            FROM documents
            WHERE tenant_id = ? AND doc_id IN ({placeholders})
            """,
            doc_params,
        ).fetchone()

        chunk_count = conn.execute(
            f"SELECT COUNT(*) AS c FROM chunks WHERE tenant_id = ? AND doc_id IN ({placeholders})",
            doc_params,
        ).fetchone()["c"]

        entity_count = conn.execute(
            f"""
            SELECT COUNT(DISTINCT entity_id) AS c
            FROM entity_mentions
            WHERE tenant_id = ? AND doc_id IN ({placeholders})
            """,
            doc_params,
        ).fetchone()["c"]

        rel_stats = conn.execute(
            f"""
            SELECT
                COUNT(*) AS total_edges,
                SUM(CASE WHEN is_inferred = 0 THEN 1 ELSE 0 END) AS explicit_edges,
                SUM(CASE WHEN is_inferred = 1 THEN 1 ELSE 0 END) AS inferred_edges
            FROM relationships
            WHERE tenant_id = ? AND doc_id IN ({placeholders})
            """,
            doc_params,
        ).fetchone()

        store = KnowledgeGraphStore()
        auth_communities = store.get_communities(t_id, doc_ids=auth_doc_ids)
        comm_count = len(auth_communities)

        uncertain_count = conn.execute(
            f"""
            SELECT COUNT(*) AS c FROM uncertain_matches
            WHERE tenant_id = ? AND doc_id IN ({placeholders})
            """,
            doc_params,
        ).fetchone()["c"]

        query_stats = conn.execute(
            """
            SELECT
                COUNT(*) AS total_queries,
                AVG(latency_ms) AS avg_latency_ms,
                SUM(CASE WHEN abstained = 1 THEN 1 ELSE 0 END) AS abstained_queries,
                SUM(prompt_injection_blocked) AS total_injections_blocked
            FROM query_logs
            WHERE tenant_id = ?
            """,
            (t_id,),
        ).fetchone()

        entity_type_rows = conn.execute(
            f"""
            SELECT e.entity_type, COUNT(DISTINCT e.entity_id) AS count
            FROM entities e
            JOIN entity_mentions em ON e.tenant_id = em.tenant_id AND e.entity_id = em.entity_id
            WHERE e.tenant_id = ? AND em.doc_id IN ({placeholders})
            GROUP BY e.entity_type
            ORDER BY count DESC
            """,
            doc_params,
        ).fetchall()

        rel_type_rows = conn.execute(
            f"""
            SELECT relationship_type, COUNT(*) AS count
            FROM relationships
            WHERE tenant_id = ? AND doc_id IN ({placeholders})
            GROUP BY relationship_type
            ORDER BY count DESC
            """,
            doc_params,
        ).fetchall()

    return {
        "tenant_id": t_id,
        "documents": {
            "total": int(doc_stats["total_docs"] or 0),
            "completed": int(doc_stats["completed_docs"] or 0),
            "failed": int(doc_stats["failed_docs"] or 0),
            "synthetic_demo_count": int(doc_stats["demo_docs"] or 0),
        },
        "knowledge_graph": {
            "chunks": int(chunk_count or 0),
            "entities": int(entity_count or 0),
            "relationships": int(rel_stats["total_edges"] or 0),
            "explicit_relationships": int(rel_stats["explicit_edges"] or 0),
            "inferred_relationships": int(rel_stats["inferred_edges"] or 0),
            "communities": int(comm_count or 0),
            "uncertain_entity_matches": int(uncertain_count or 0),
            "entity_types": [dict(r) for r in entity_type_rows],
            "relationship_types": [dict(r) for r in rel_type_rows],
        },
        "queries": {
            "total": int(query_stats["total_queries"] or 0),
            "avg_latency_ms": round(float(query_stats["avg_latency_ms"] or 0.0), 2),
            "abstained": int(query_stats["abstained_queries"] or 0),
            "prompt_injections_blocked": int(query_stats["total_injections_blocked"] or 0),
        },
    }


@app.get("/api/documents", response_model=List[DocumentSummary])
def list_documents(
    principal: Principal = Depends(resolve_principal),
) -> List[DocumentSummary]:
    """List documents in the caller's tenant that the caller is authorized to view."""
    require_permission(principal, "documents:read")
    t_id = principal.tenant_id
    auth_doc_ids = set(get_authorized_doc_ids_for_principal(principal))
    if not auth_doc_ids:
        return []

    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT doc_id, tenant_id, filename, mime_type, file_size, sha256,
                   status, is_synthetic_demo, owner_user_id, visibility,
                   allowed_roles_json, allowed_user_ids_json,
                   error_message, metadata_json, created_at, updated_at
            FROM documents
            WHERE tenant_id = ?
            ORDER BY updated_at DESC
            """,
            (t_id,),
        ).fetchall()

        results: List[DocumentSummary] = []
        for r in rows:
            did = r["doc_id"]
            if did not in auth_doc_ids:
                continue
            c_cnt = conn.execute(
                "SELECT COUNT(*) AS c FROM chunks WHERE tenant_id = ? AND doc_id = ?",
                (t_id, did),
            ).fetchone()["c"]
            e_cnt = conn.execute(
                "SELECT COUNT(DISTINCT entity_id) AS c FROM entity_mentions WHERE tenant_id = ? AND doc_id = ?",
                (t_id, did),
            ).fetchone()["c"]
            r_cnt = conn.execute(
                "SELECT COUNT(*) AS c FROM relationships WHERE tenant_id = ? AND doc_id = ?",
                (t_id, did),
            ).fetchone()["c"]
            meta = json.loads(r["metadata_json"] or "{}")
            try:
                allowed_roles = json.loads(r["allowed_roles_json"] or '["admin","analyst","viewer"]')
            except Exception:
                allowed_roles = ["admin", "analyst", "viewer"]
            try:
                allowed_users = json.loads(r["allowed_user_ids_json"] or "[]")
            except Exception:
                allowed_users = []

            results.append(
                DocumentSummary(
                    doc_id=did,
                    tenant_id=r["tenant_id"],
                    filename=r["filename"],
                    mime_type=r["mime_type"],
                    file_size=int(r["file_size"]),
                    sha256=r["sha256"],
                    status=r["status"],
                    is_synthetic_demo=bool(r["is_synthetic_demo"]),
                    owner_user_id=r["owner_user_id"] or "user-admin",
                    visibility=r["visibility"] or "tenant",
                    allowed_roles=allowed_roles,
                    allowed_user_ids=allowed_users,
                    chunk_count=int(c_cnt),
                    entity_count=int(e_cnt),
                    relationship_count=int(r_cnt),
                    error_message=r["error_message"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                    metadata=meta,
                )
            )
    return results


@app.post("/api/documents/upload")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    is_synthetic_demo: bool = Form(default=False),
    visibility: str = Form(default="tenant"),
    allowed_roles: Optional[str] = Form(default=None),
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Validate, ingest, extract, and index an uploaded document with ACL metadata."""
    require_role(principal, ("admin", "analyst"))
    raw_bytes = await file.read()
    filename = file.filename or "uploaded_document.txt"
    validate_upload_file(filename, file.content_type, raw_bytes)

    vis_clean = visibility if visibility in ("tenant", "restricted", "private") else "tenant"
    roles_list = ["admin", "analyst", "viewer"]
    if allowed_roles:
        parsed_roles = [
            r.strip()
            for r in allowed_roles.split(",")
            if r.strip() in ("admin", "analyst", "viewer")
        ]
        if parsed_roles:
            roles_list = list(dict.fromkeys(["admin"] + parsed_roles))

    try:
        result = ingest_and_index_document(
            tenant_id=principal.tenant_id,
            filename=filename,
            raw_bytes=raw_bytes,
            mime_type=file.content_type or "text/plain",
            is_synthetic_demo=is_synthetic_demo,
            owner_user_id=principal.user_id,
            visibility=vis_clean,
            allowed_roles=roles_list,
        )
        record_audit_event(
            tenant_id=principal.tenant_id,
            actor_user_id=principal.user_id,
            actor_username=principal.username,
            actor_role=principal.role,
            action="documents.upload",
            target_type="document",
            target_id=result["doc_id"],
            status="success",
            ip_address=_client_ip(request),
            details={"filename": filename, "visibility": vis_clean, "allowed_roles": roles_list},
        )
        return result
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


@app.post("/api/documents/load-demo-fixtures")
def load_demo_fixtures(
    request: Request,
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Load the clearly labeled 3-document synthetic demo corpus into the caller's tenant."""
    require_role(principal, ("admin", "analyst"))
    ingested: List[Dict[str, Any]] = []
    for doc in SYNTHETIC_DEMO_DOCUMENTS:
        res = ingest_and_index_document(
            tenant_id=principal.tenant_id,
            filename=doc["filename"],
            raw_bytes=doc["content"].encode("utf-8"),
            mime_type=doc["mime_type"],
            is_synthetic_demo=True,
            owner_user_id=principal.user_id,
        )
        ingested.append(res)

    record_audit_event(
        tenant_id=principal.tenant_id,
        actor_user_id=principal.user_id,
        actor_username=principal.username,
        actor_role=principal.role,
        action="documents.load_demo_fixtures",
        target_type="corpus",
        target_id=principal.tenant_id,
        status="success",
        ip_address=_client_ip(request),
        details={"ingested_count": len(ingested)},
    )
    return {
        "label": "[SYNTHETIC DEMO FIXTURE CORPUS]",
        "ingested_count": len(ingested),
        "documents": ingested,
    }


@app.put("/api/documents/{doc_id}/acl")
def update_document_acl(
    doc_id: str,
    req: DocumentACLUpdateRequest,
    request: Request,
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Update document-level visibility, allowed roles, and allowed user IDs."""
    require_role(principal, ("admin", "analyst"))
    t_id = principal.tenant_id

    with get_db_connection() as conn:
        doc = conn.execute(
            "SELECT doc_id, filename, owner_user_id FROM documents WHERE tenant_id = ? AND doc_id = ?",
            (t_id, doc_id),
        ).fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found in tenant scope.")

        if principal.role != "admin" and doc["owner_user_id"] != principal.user_id:
            record_audit_event(
                tenant_id=t_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                actor_role=principal.role,
                action="documents.update_acl",
                target_type="document",
                target_id=doc_id,
                status="denied",
                ip_address=_client_ip(request),
                details={"reason": "not_document_owner"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators or the document owner can modify document access controls.",
            )

        valid_roles = [r for r in req.allowed_roles if r in ("admin", "analyst", "viewer")]
        if "admin" not in valid_roles:
            valid_roles.insert(0, "admin")

        conn.execute(
            """
            UPDATE documents
            SET visibility = ?, allowed_roles_json = ?, allowed_user_ids_json = ?, updated_at = ?
            WHERE tenant_id = ? AND doc_id = ?
            """,
            (
                req.visibility,
                json.dumps(valid_roles),
                json.dumps(req.allowed_user_ids),
                utc_now_iso(),
                t_id,
                doc_id,
            ),
        )

    record_audit_event(
        tenant_id=t_id,
        actor_user_id=principal.user_id,
        actor_username=principal.username,
        actor_role=principal.role,
        action="documents.update_acl",
        target_type="document",
        target_id=doc_id,
        status="success",
        ip_address=_client_ip(request),
        details={
            "visibility": req.visibility,
            "allowed_roles": valid_roles,
            "allowed_user_ids": req.allowed_user_ids,
        },
    )
    return {
        "status": "acl_updated",
        "doc_id": doc_id,
        "visibility": req.visibility,
        "allowed_roles": valid_roles,
        "allowed_user_ids": req.allowed_user_ids,
    }


@app.get("/api/documents/{doc_id}/chunks")
def get_document_chunks(
    doc_id: str,
    request: Request,
    principal: Principal = Depends(resolve_principal),
) -> List[Dict[str, Any]]:
    """Retrieve preprocessed chunks for a specific authorized document in the caller's tenant."""
    require_permission(principal, "documents:read")
    with get_db_connection() as conn:
        doc = conn.execute(
            "SELECT doc_id, filename FROM documents WHERE tenant_id = ? AND doc_id = ?",
            (principal.tenant_id, doc_id),
        ).fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found in tenant scope.")

        auth_docs = set(get_authorized_doc_ids_for_principal(principal))
        if doc_id not in auth_docs:
            record_audit_event(
                tenant_id=principal.tenant_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                actor_role=principal.role,
                action="documents.read_chunks",
                target_type="document",
                target_id=doc_id,
                status="denied",
                ip_address=_client_ip(request),
                details={"reason": "document_acl_restricted"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: you do not have permission to view this restricted document.",
            )

        rows = conn.execute(
            """
            SELECT chunk_id, doc_id, chunk_index, page_number, section_title,
                   text, char_start, char_end, token_count, embedding_model
            FROM chunks
            WHERE tenant_id = ? AND doc_id = ?
            ORDER BY chunk_index ASC
            """,
            (principal.tenant_id, doc_id),
        ).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/documents/{doc_id}")
def delete_document(
    doc_id: str,
    request: Request,
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Delete a document and cascade-clean its chunks, edges, and orphaned entities."""
    require_role(principal, ("admin", "analyst"))
    auth_docs = set(get_authorized_doc_ids_for_principal(principal))
    with get_db_connection() as conn:
        doc = conn.execute(
            "SELECT doc_id, filename FROM documents WHERE tenant_id = ? AND doc_id = ?",
            (principal.tenant_id, doc_id),
        ).fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found in tenant scope.")
        if doc_id not in auth_docs:
            record_audit_event(
                tenant_id=principal.tenant_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                actor_role=principal.role,
                action="documents.delete",
                target_type="document",
                target_id=doc_id,
                status="denied",
                ip_address=_client_ip(request),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: you are not authorized to delete this document.",
            )

    store = KnowledgeGraphStore()
    deleted = store.delete_document_and_artifacts(principal.tenant_id, doc_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Document not found in tenant scope.")

    record_audit_event(
        tenant_id=principal.tenant_id,
        actor_user_id=principal.user_id,
        actor_username=principal.username,
        actor_role=principal.role,
        action="documents.delete",
        target_type="document",
        target_id=doc_id,
        status="success",
        ip_address=_client_ip(request),
        details={"filename": doc["filename"]},
    )
    return {"status": "deleted", "doc_id": doc_id}


@app.get("/api/graph/subgraph")
def get_graph_subgraph(
    request: Request,
    search: Optional[str] = Query(default=None, max_length=200),
    entity_type: Optional[str] = Query(default=None),
    relationship_type: Optional[str] = Query(default=None),
    doc_id: Optional[str] = Query(default=None),
    include_inferred: bool = Query(default=True),
    limit_nodes: int = Query(default=80, ge=5, le=200),
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Explore bounded knowledge graph nodes, edges, and provenance within tenant & ACL scope."""
    require_permission(principal, "graph:read")
    if search:
        try:
            CypherGuard.reject_raw_cypher(search)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if entity_type:
        try:
            CypherGuard.validate_label(entity_type)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if relationship_type:
        try:
            CypherGuard.validate_relationship_type(relationship_type)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    all_auth_docs = get_authorized_doc_ids_for_principal(principal)
    if doc_id and doc_id not in all_auth_docs:
        record_audit_event(
            tenant_id=principal.tenant_id,
            actor_user_id=principal.user_id,
            actor_username=principal.username,
            actor_role=principal.role,
            action="graph.subgraph",
            target_type="document",
            target_id=doc_id,
            status="denied",
            ip_address=_client_ip(request),
            details={"reason": "unauthorized_doc_id_filter"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you are not authorized to inspect graph artifacts for that document.",
        )

    scoped_doc_ids = [doc_id] if doc_id else all_auth_docs
    store = KnowledgeGraphStore()
    return store.explore_subgraph(
        tenant_id=principal.tenant_id,
        search_query=search,
        entity_type=entity_type,
        relationship_type=relationship_type,
        doc_id=doc_id,
        doc_ids=scoped_doc_ids,
        include_inferred=include_inferred,
        limit_nodes=limit_nodes,
    )


@app.get("/api/graph/communities")
def list_communities(
    principal: Principal = Depends(resolve_principal),
) -> List[Dict[str, Any]]:
    """Return detected knowledge graph communities scoped to the caller's authorized documents."""
    require_permission(principal, "graph:read")
    auth_doc_ids = get_authorized_doc_ids_for_principal(principal)
    store = KnowledgeGraphStore()
    return [c.model_dump() for c in store.get_communities(principal.tenant_id, doc_ids=auth_doc_ids)]


@app.get("/api/graph/uncertain-matches")
def list_uncertain_matches(
    principal: Principal = Depends(resolve_principal),
) -> List[Dict[str, Any]]:
    """Return tracked uncertain entity resolution pairs scoped to authorized documents."""
    require_permission(principal, "graph:read")
    auth_doc_ids = get_authorized_doc_ids_for_principal(principal)
    if not auth_doc_ids:
        return []
    placeholders = ",".join("?" for _ in auth_doc_ids)
    with get_db_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT match_id, tenant_id, entity_a_id, entity_a_name,
                   entity_b_id, entity_b_name, entity_type,
                   similarity_score, reason, doc_id, created_at
            FROM uncertain_matches
            WHERE tenant_id = ? AND doc_id IN ({placeholders})
            ORDER BY similarity_score DESC
            """,
            (principal.tenant_id, *auth_doc_ids),
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/query", response_model=QueryResponse)
def execute_query(
    req: QueryRequest,
    request: Request,
    principal: Principal = Depends(resolve_principal),
) -> QueryResponse:
    """
    Execute an analytical question using hybrid GraphRAG or baseline retrieval,
    enforcing document-level ACLs before chunks, graph nodes, or citations reach the LLM.
    """
    require_permission(principal, "query:execute")
    try:
        CypherGuard.reject_raw_cypher(req.question)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    all_auth_docs = set(get_authorized_doc_ids_for_principal(principal))
    if req.doc_ids:
        unauthorized_requested = [d for d in req.doc_ids if d not in all_auth_docs]
        if unauthorized_requested:
            record_audit_event(
                tenant_id=principal.tenant_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                actor_role=principal.role,
                action="query.execute",
                target_type="document",
                target_id=",".join(unauthorized_requested),
                status="denied",
                ip_address=_client_ip(request),
                details={"reason": "unauthorized_doc_ids_requested"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: query references one or more documents outside your authorized scope.",
            )

    authorized_doc_ids = get_authorized_doc_ids_for_principal(principal, req.doc_ids)

    t0 = time.perf_counter()
    ret = execute_hybrid_retrieval(
        tenant_id=principal.tenant_id,
        question=req.question,
        strategy=req.strategy,
        top_k_chunks=req.top_k_chunks,
        max_hops=req.max_hops,
        include_inferred=req.include_inferred,
        doc_ids=authorized_doc_ids,
    )

    gen = synthesize_grounded_answer(
        question=req.question,
        routed_strategy=ret["routed_strategy"],
        citations=ret["citations"],
        graph_paths=ret["graph_paths"],
        communities=ret["communities_used"],
    )

    latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    now = utc_now_iso()
    q_hash = hashlib.sha256(
        f"{principal.tenant_id}::{req.question}::{time.time_ns()}".encode("utf-8")
    ).hexdigest()[:12]
    query_id = f"qry-{q_hash}"

    metrics = {
        "citation_count": len(gen["citations"]),
        "graph_path_count": len(ret["graph_paths"]),
        "community_count": len(ret["communities_used"]),
        "contradictions_count": len(gen["contradictions_detected"]),
        "prompt_injection_warnings_count": len(gen["prompt_injection_warnings"]),
        "authorized_doc_count": len(authorized_doc_ids),
        "llm_provider": settings.llm_provider,
        "embedding_provider": settings.embedding_provider,
    }

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO query_logs (
                query_id, tenant_id, user_id, question, routed_strategy,
                abstained, latency_ms, citation_count, graph_path_count,
                prompt_injection_blocked, metrics_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                query_id,
                principal.tenant_id,
                principal.user_id,
                req.question,
                ret["routed_strategy"],
                1 if gen["abstained"] else 0,
                latency_ms,
                len(gen["citations"]),
                len(ret["graph_paths"]),
                len(gen["prompt_injection_warnings"]),
                json.dumps(metrics),
                now,
            ),
        )

    return QueryResponse(
        query_id=query_id,
        question=req.question,
        routed_strategy=ret["routed_strategy"],
        answer=gen["answer"],
        abstained=gen["abstained"],
        abstention_reason=gen["abstention_reason"],
        contradictions_detected=gen["contradictions_detected"],
        prompt_injection_warnings=gen["prompt_injection_warnings"],
        citations=gen["citations"],
        graph_paths=ret["graph_paths"],
        communities_used=ret["communities_used"],
        retrieval_explanation=ret["retrieval_explanation"],
        latency_ms=latency_ms,
        metrics=metrics,
    )


@app.post("/api/evaluation/run")
def run_evaluation_endpoint(
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Run the reproducible benchmark comparing Conventional Vector RAG vs. Hybrid GraphRAG."""
    require_role(principal, ("admin", "analyst"))
    return run_comparative_evaluation(tenant_id=principal.tenant_id)


@app.get("/api/jobs")
def list_jobs(
    limit: int = Query(default=30, ge=1, le=100),
    principal: Principal = Depends(resolve_principal),
) -> List[Dict[str, Any]]:
    """List genuine ingestion and pipeline jobs for the caller's tenant."""
    require_permission(principal, "jobs:read")
    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT job_id, tenant_id, doc_id, job_type, status, stage,
                   progress_pct, details_json, error_message, started_at, finished_at
            FROM jobs
            WHERE tenant_id = ?
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (principal.tenant_id, limit),
        ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d.pop("details_json", "{}") or "{}")
        out.append(d)
    return out


@app.get("/api/observability/logs")
def list_query_logs(
    limit: int = Query(default=30, ge=1, le=100),
    principal: Principal = Depends(resolve_principal),
) -> List[Dict[str, Any]]:
    """Return safe operational query telemetry logs scoped to the caller's tenant."""
    require_permission(principal, "observability:read")
    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT query_id, user_id, question, routed_strategy, abstained,
                   latency_ms, citation_count, graph_path_count,
                   prompt_injection_blocked, metrics_json, created_at
            FROM query_logs
            WHERE tenant_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (principal.tenant_id, limit),
        ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["metrics"] = json.loads(d.pop("metrics_json", "{}") or "{}")
        out.append(d)
    return out


@app.get("/api/config")
def get_sanitized_config(
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Return sanitized runtime configuration (never exposes secrets or API keys)."""
    require_permission(principal, "config:read")
    return {
        "config": settings.to_sanitized_dict(),
        "caller": principal.model_dump(),
    }


@app.put("/api/config")
def update_runtime_config(
    req: ConfigUpdateRequest,
    request: Request,
    principal: Principal = Depends(resolve_principal),
) -> Dict[str, Any]:
    """Update supported runtime model, embedding, and retrieval settings (Admin role required)."""
    require_role(principal, ("admin",))
    update_data = req.model_dump(exclude_none=True)
    for k, v in update_data.items():
        if hasattr(settings, k):
            setattr(settings, k, v)
    record_audit_event(
        tenant_id=principal.tenant_id,
        actor_user_id=principal.user_id,
        actor_username=principal.username,
        actor_role=principal.role,
        action="config.update",
        target_type="config",
        target_id="runtime_settings",
        status="success",
        ip_address=_client_ip(request),
        details=update_data,
    )
    return {
        "status": "updated",
        "config": settings.to_sanitized_dict(),
    }


# Serve Frontend UI static files if present
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
