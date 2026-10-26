"""Transactional SQLite database management and schema setup for Automated GraphRAG."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from backend.config import settings

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT NOT NULL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active INTEGER NOT NULL DEFAULT 1,
    allowed_doc_ids_json TEXT NOT NULL DEFAULT '["*"]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_tenant_role ON users(tenant_id, role);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '127.0.0.1',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id TEXT NOT NULL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    actor_user_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '127.0.0.1',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_created ON audit_logs(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS documents (
    doc_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    is_synthetic_demo INTEGER NOT NULL DEFAULT 0,
    owner_user_id TEXT NOT NULL DEFAULT 'user-admin',
    visibility TEXT NOT NULL DEFAULT 'tenant',
    allowed_roles_json TEXT NOT NULL DEFAULT '["admin","analyst","viewer"]',
    allowed_user_ids_json TEXT NOT NULL DEFAULT '[]',
    error_message TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, doc_id)
);

CREATE INDEX IF NOT EXISTS idx_documents_tenant_sha ON documents(tenant_id, sha256);

CREATE TABLE IF NOT EXISTS chunks (
    chunk_id TEXT NOT NULL,
    doc_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    page_number INTEGER NOT NULL DEFAULT 1,
    section_title TEXT NOT NULL DEFAULT 'Root',
    text TEXT NOT NULL,
    char_start INTEGER NOT NULL,
    char_end INTEGER NOT NULL,
    token_count INTEGER NOT NULL,
    embedding_json TEXT,
    embedding_model TEXT,
    PRIMARY KEY (tenant_id, chunk_id),
    FOREIGN KEY (tenant_id, doc_id) REFERENCES documents(tenant_id, doc_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_chunks_doc ON chunks(tenant_id, doc_id);

CREATE TABLE IF NOT EXISTS entities (
    entity_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    canonical_name TEXT NOT NULL,
    normalized_key TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.85,
    community_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, entity_id),
    UNIQUE (tenant_id, normalized_key, entity_type)
);

CREATE INDEX IF NOT EXISTS idx_entities_tenant_type ON entities(tenant_id, entity_type);

CREATE TABLE IF NOT EXISTS entity_mentions (
    mention_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    doc_id TEXT NOT NULL,
    chunk_id TEXT NOT NULL,
    surface_form TEXT NOT NULL,
    evidence_quote TEXT NOT NULL,
    char_start INTEGER NOT NULL,
    char_end INTEGER NOT NULL,
    confidence REAL NOT NULL,
    PRIMARY KEY (tenant_id, mention_id),
    FOREIGN KEY (tenant_id, entity_id) REFERENCES entities(tenant_id, entity_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, doc_id) REFERENCES documents(tenant_id, doc_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, chunk_id) REFERENCES chunks(tenant_id, chunk_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mentions_doc ON entity_mentions(tenant_id, doc_id);
CREATE INDEX IF NOT EXISTS idx_mentions_entity ON entity_mentions(tenant_id, entity_id);

CREATE TABLE IF NOT EXISTS relationships (
    edge_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    is_inferred INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0.8,
    doc_id TEXT NOT NULL,
    chunk_id TEXT NOT NULL,
    evidence_quote TEXT NOT NULL,
    char_start INTEGER NOT NULL DEFAULT 0,
    char_end INTEGER NOT NULL DEFAULT 0,
    temporal_marker TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, edge_id),
    FOREIGN KEY (tenant_id, source_id) REFERENCES entities(tenant_id, entity_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, target_id) REFERENCES entities(tenant_id, entity_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, doc_id) REFERENCES documents(tenant_id, doc_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, chunk_id) REFERENCES chunks(tenant_id, chunk_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_rel_doc ON relationships(tenant_id, doc_id);
CREATE INDEX IF NOT EXISTS idx_rel_src ON relationships(tenant_id, source_id);
CREATE INDEX IF NOT EXISTS idx_rel_tgt ON relationships(tenant_id, target_id);

CREATE TABLE IF NOT EXISTS uncertain_matches (
    match_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    entity_a_id TEXT NOT NULL,
    entity_a_name TEXT NOT NULL,
    entity_b_id TEXT NOT NULL,
    entity_b_name TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    similarity_score REAL NOT NULL,
    reason TEXT NOT NULL,
    doc_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, match_id)
);

CREATE TABLE IF NOT EXISTS communities (
    community_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    level INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    entity_ids_json TEXT NOT NULL,
    entity_names_json TEXT NOT NULL,
    relationship_count INTEGER NOT NULL DEFAULT 0,
    dominant_types_json TEXT NOT NULL DEFAULT '[]',
    source_doc_ids_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, community_id)
);

CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    doc_id TEXT,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL,
    stage TEXT NOT NULL,
    progress_pct INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    error_message TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    PRIMARY KEY (tenant_id, job_id)
);

CREATE TABLE IF NOT EXISTS query_logs (
    query_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    question TEXT NOT NULL,
    routed_strategy TEXT NOT NULL,
    abstained INTEGER NOT NULL DEFAULT 0,
    latency_ms REAL NOT NULL,
    citation_count INTEGER NOT NULL DEFAULT 0,
    graph_path_count INTEGER NOT NULL DEFAULT 0,
    prompt_injection_blocked INTEGER NOT NULL DEFAULT 0,
    metrics_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, query_id)
);
"""


def get_db_path(custom_path: str | None = None) -> Path:
    """Resolve and ensure parent directory exists for SQLite database."""
    target = Path(custom_path or settings.sqlite_db_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def _run_column_migrations(conn: sqlite3.Connection) -> None:
    """Safely add new columns to existing SQLite tables if upgrading an existing database file."""
    doc_cols = {
        row[1] for row in conn.execute("PRAGMA table_info(documents);").fetchall()
    }
    migrations = [
        ("owner_user_id", "ALTER TABLE documents ADD COLUMN owner_user_id TEXT NOT NULL DEFAULT 'user-admin';"),
        ("visibility", "ALTER TABLE documents ADD COLUMN visibility TEXT NOT NULL DEFAULT 'tenant';"),
        ("allowed_roles_json", "ALTER TABLE documents ADD COLUMN allowed_roles_json TEXT NOT NULL DEFAULT '[\"admin\",\"analyst\",\"viewer\"]';"),
        ("allowed_user_ids_json", "ALTER TABLE documents ADD COLUMN allowed_user_ids_json TEXT NOT NULL DEFAULT '[]';"),
    ]
    for col_name, ddl in migrations:
        if col_name not in doc_cols:
            conn.execute(ddl)


def init_db(custom_path: str | None = None) -> None:
    """Initialize SQLite schema with WAL mode, foreign keys, migrations, and bootstrap users."""
    db_path = get_db_path(custom_path)
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.executescript(SCHEMA_SQL)
        _run_column_migrations(conn)
        conn.commit()
    finally:
        conn.close()

    # Seed initial accounts if users table is empty
    from backend.auth import seed_default_users

    seed_default_users(str(db_path))


@contextmanager
def get_db_connection(custom_path: str | None = None) -> Iterator[sqlite3.Connection]:
    """Provide a transactional SQLite connection with Row factory and foreign keys enabled."""
    db_path = get_db_path(custom_path)
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
