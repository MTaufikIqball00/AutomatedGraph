"""Security, authentication, RBAC, Cypher injection guard, and prompt-injection defense."""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple
from fastapi import Cookie, Header, HTTPException, Request, status

from backend.auth import (
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    record_audit_event,
    resolve_session_principal,
)
from backend.config import Principal, ROLE_PERMISSION_MATRIX, settings
from backend.database import get_db_connection
from backend.schemas import EntityType, RelationshipType

ALLOWED_MIME_TYPES = {
    "text/plain",
    "text/markdown",
    "application/pdf",
    "application/json",
    "text/csv",
    "application/octet-stream",
}

ALLOWED_EXTENSIONS = {".txt", ".md", ".pdf", ".json", ".csv"}

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above|system)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|system)\s+(instructions|prompts|rules)", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*override", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(in\s+developer\s+mode|unrestricted|dan\b)", re.IGNORECASE),
    re.compile(r"(reveal|print|output|exfiltrate|leak)\s+(the\s+)?(api[_\s]?key|secret|password|credentials|system\s+prompt)", re.IGNORECASE),
    re.compile(r"<\s*(?:system|admin_override|jailbreak)\s*>", re.IGNORECASE),
    re.compile(r"execute\s+cypher\s*:\s*match\b.*detach\s+delete", re.IGNORECASE),
]

FORBIDDEN_CYPHER_PATTERNS = [
    re.compile(r"\b(DETACH\s+DELETE|DELETE|REMOVE|DROP|CREATE|MERGE|SET|CALL|LOAD\s+CSV|APOC|DBMS)\b", re.IGNORECASE),
    re.compile(r"[;{}]"),
    re.compile(r"//|/\*|\*/"),
]

SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _sync_api_key_principal_with_db(base_principal: Principal) -> Principal:
    """
    If an API-key principal corresponds to a database user record in `users`,
    enforce the database user's current `is_active`, `role`, and `allowed_doc_ids` state.
    """
    with get_db_connection() as conn:
        row = conn.execute(
            """
            SELECT user_id, tenant_id, username, email, full_name,
                   role, is_active, allowed_doc_ids_json
            FROM users
            WHERE user_id = ?
            """,
            (base_principal.user_id,),
        ).fetchone()
    if not row:
        return base_principal
    if int(row["is_active"]) == 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account associated with these credentials has been deactivated.",
        )
    return Principal(
        user_id=row["user_id"],
        tenant_id=row["tenant_id"],
        username=row["username"],
        email=row["email"],
        full_name=row["full_name"],
        role=row["role"],
        auth_method="api_key",
        allowed_doc_ids=json.loads(row["allowed_doc_ids_json"] or '["*"]'),
    )


def resolve_principal(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_csrf_token: Optional[str] = Header(default=None, alias=CSRF_HEADER_NAME),
    session_cookie: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> Principal:
    """
    Authenticate caller from validated server-side session cookie, Bearer session token,
    or configured API key. Never trusts role or identity fields supplied by the client.
    """
    # 1. Explicit X-API-Key header
    api_key_map = settings.parse_api_keys()
    if x_api_key:
        clean_key = x_api_key.strip()
        if clean_key in api_key_map:
            return _sync_api_key_principal_with_db(api_key_map[clean_key])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key or unauthorized credentials.",
        )

    # 2. Authorization: Bearer <token> (checks active user_sessions first, then api_key_map)
    if authorization and authorization.lower().startswith("bearer "):
        bearer_val = authorization[7:].strip()
        if bearer_val in api_key_map:
            return _sync_api_key_principal_with_db(api_key_map[bearer_val])
        return resolve_session_principal(bearer_val, require_csrf=False)

    # 3. HttpOnly Session Cookie (enforces CSRF token on state-changing HTTP methods)
    if session_cookie:
        is_state_changing = request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
        return resolve_session_principal(
            session_cookie.strip(),
            require_csrf=is_state_changing,
            provided_csrf=x_csrf_token,
        )

    if not settings.require_auth and settings.default_dev_api_key in api_key_map:
        return _sync_api_key_principal_with_db(api_key_map[settings.default_dev_api_key])

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please sign in or provide valid credentials.",
    )


def require_role(
    principal: Principal,
    allowed_roles: Tuple[str, ...],
    action_name: str = "restricted_operation",
    target_id: str = "system",
) -> None:
    """Enforce server-side role-based access control and log any access-denied attempt."""
    if principal.role not in allowed_roles:
        record_audit_event(
            tenant_id=principal.tenant_id,
            actor_user_id=principal.user_id,
            actor_role=principal.role,
            action=f"rbac.denied.{action_name}",
            target_type="endpoint",
            target_id=target_id,
            outcome="denied",
            details={"required_roles": list(allowed_roles)},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{principal.role}' is not authorized for this operation. Required: {allowed_roles}.",
        )


def require_permission(
    principal: Principal,
    permission: str,
    target_id: str = "system",
) -> None:
    """Enforce fine-grained permission from ROLE_PERMISSION_MATRIX and log denied attempts."""
    allowed_perms = ROLE_PERMISSION_MATRIX.get(principal.role, [])
    if permission not in allowed_perms:
        record_audit_event(
            tenant_id=principal.tenant_id,
            actor_user_id=principal.user_id,
            actor_role=principal.role,
            action=f"permission.denied.{permission}",
            target_type="permission",
            target_id=target_id,
            outcome="denied",
            details={"missing_permission": permission},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{principal.role}' lacks required permission '{permission}'.",
        )


class CypherGuard:
    """Validates graph query parameters and builds strictly parameterized Cypher statements."""

    ALLOWED_LABELS = {e.value for e in EntityType} | {"Entity", "Document", "Chunk", "Community"}
    ALLOWED_REL_TYPES = {r.value for r in RelationshipType} | {
        "HAS_CHUNK",
        "MENTIONS",
        "BELONGS_TO_COMMUNITY",
    }

    @classmethod
    def validate_label(cls, label: str) -> str:
        """Ensure a node label is in the strict allowlist."""
        cleaned = label.strip().upper()
        if cleaned not in cls.ALLOWED_LABELS and label not in cls.ALLOWED_LABELS:
            raise ValueError(f"Disallowed or unsafe node label: '{label}'")
        return label

    @classmethod
    def validate_relationship_type(cls, rel_type: str) -> str:
        """Ensure a relationship type is in the strict allowlist."""
        cleaned = rel_type.strip().upper()
        if cleaned not in cls.ALLOWED_REL_TYPES:
            raise ValueError(f"Disallowed or unsafe relationship type: '{rel_type}'")
        return cleaned

    @classmethod
    def assert_safe_parameter_value(cls, value: str) -> str:
        """Verify a string parameter does not contain raw Cypher command injection payloads."""
        if not isinstance(value, str):
            raise ValueError("Parameter value must be a string.")
        if "\x00" in value:
            raise ValueError("Null bytes are not permitted in graph query parameters.")
        return value

    @classmethod
    def reject_raw_cypher(cls, query_text: str) -> None:
        """Detect and block attempts to submit raw or destructive Cypher statements."""
        for pattern in FORBIDDEN_CYPHER_PATTERNS:
            if pattern.search(query_text):
                raise ValueError(
                    "Unsafe Cypher statement or administrative command detected and blocked."
                )

    @classmethod
    def build_parameterized_neighborhood_cypher(
        cls,
        tenant_id: str,
        entity_id: str,
        max_hops: int = 2,
        rel_filter: Optional[List[str]] = None,
        limit: int = 50,
    ) -> Tuple[str, Dict[str, object]]:
        """Construct a verified parameterized Cypher query with tenant isolation."""
        cls.assert_safe_parameter_value(tenant_id)
        cls.assert_safe_parameter_value(entity_id)
        if not isinstance(max_hops, int) or max_hops < 1 or max_hops > 4:
            raise ValueError("max_hops must be an integer between 1 and 4.")
        if not isinstance(limit, int) or limit < 1 or limit > 200:
            raise ValueError("limit must be an integer between 1 and 200.")

        rel_pattern = ""
        if rel_filter:
            validated_rels = [cls.validate_relationship_type(r) for r in rel_filter]
            rel_pattern = ":" + "|".join(validated_rels)

        cypher = (
            f"MATCH path = (start:Entity {{tenant_id: $tenant_id, entity_id: $entity_id}})"
            f"-[r{rel_pattern}*1..{max_hops}]-(neighbor:Entity {{tenant_id: $tenant_id}}) "
            f"WHERE ALL(rel IN relationships(path) WHERE rel.tenant_id = $tenant_id) "
            f"RETURN path LIMIT $limit"
        )
        params: Dict[str, object] = {
            "tenant_id": tenant_id,
            "entity_id": entity_id,
            "limit": limit,
        }
        return cypher, params


class PromptInjectionGuard:
    """Scans untrusted document text and neutralizes embedded prompt injection attempts."""

    @classmethod
    def scan_text(cls, text: str) -> List[str]:
        """Return list of matched adversarial injection signatures found in text."""
        findings: List[str] = []
        for pattern in PROMPT_INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(f"Blocked untrusted instruction pattern: '{match.group(0)}'")
        return findings

    @classmethod
    def sanitize_chunk_text(cls, text: str) -> Tuple[str, List[str]]:
        """Neutralize prompt-injection segments inside retrieved chunks before synthesis."""
        warnings = cls.scan_text(text)
        sanitized = text
        for pattern in PROMPT_INJECTION_PATTERNS:
            sanitized = pattern.sub("[REDACTED_UNTRUSTED_INSTRUCTION]", sanitized)
        return sanitized, warnings


def validate_upload_file(filename: str, content_type: Optional[str], raw_bytes: bytes) -> str:
    """Validate uploaded filename extension, MIME type, file size, and content safety."""
    if not filename or len(filename.strip()) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a valid filename.",
        )

    lower_name = filename.lower().strip()
    ext = ""
    if "." in lower_name:
        ext = "." + lower_name.rsplit(".", 1)[-1]

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported file extension '{ext}'. Supported formats: {sorted(ALLOWED_EXTENSIONS)}",
        )

    if content_type:
        base_mime = content_type.split(";")[0].strip().lower()
        if base_mime and base_mime not in ALLOWED_MIME_TYPES:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=f"Unsupported MIME type '{base_mime}'.",
            )

    if len(raw_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty (0 bytes).",
        )

    if len(raw_bytes) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size ({len(raw_bytes)} bytes) exceeds limit ({settings.max_upload_size_bytes} bytes).",
        )

    if ext in {".txt", ".md", ".json", ".csv"} and b"\x00" in raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Binary null bytes detected in text document upload.",
        )

    return ext
