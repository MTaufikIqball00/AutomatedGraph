"""Configuration management for Automated GraphRAG."""
from __future__ import annotations

from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Principal(BaseModel):
    """Authenticated caller identity and authorization scope."""
    user_id: str
    tenant_id: str
    username: str = ""
    email: str = ""
    full_name: str = ""
    role: Literal["admin", "analyst", "viewer"]
    auth_method: str = "session"
    allowed_doc_ids: List[str] = Field(default_factory=lambda: ["*"])
    csrf_token: Optional[str] = None


# Documented Role-Permission Matrix enforced across all backend endpoints
ROLE_PERMISSION_MATRIX: Dict[str, List[str]] = {
    "admin": [
        "users:read",
        "users:manage",
        "users:create",
        "users:update",
        "users:deactivate",
        "users:revoke_sessions",
        "audit:read",
        "audit_logs:read",
        "config:read",
        "config:write",
        "config:update",
        "documents:read",
        "documents:upload",
        "documents:delete",
        "documents:manage_acl",
        "graph:read",
        "query:execute",
        "evaluation:run",
        "jobs:read",
        "observability:read",
    ],
    "analyst": [
        "config:read",
        "documents:read",
        "documents:upload",
        "documents:delete",
        "graph:read",
        "query:execute",
        "evaluation:run",
        "jobs:read",
        "observability:read",
    ],
    "viewer": [
        "config:read",
        "documents:read",
        "graph:read",
        "query:execute",
        "jobs:read",
        "observability:read",
    ],
}


class AppSettings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = Field(default="development", alias="APP_ENV")
    app_host: str = Field(default="127.0.0.1", alias="APP_HOST")
    app_port: int = Field(default=8765, alias="APP_PORT")

    sqlite_db_path: str = Field(default="./data/graphrag.db", alias="SQLITE_DB_PATH")
    max_upload_size_bytes: int = Field(default=10 * 1024 * 1024, alias="MAX_UPLOAD_SIZE_BYTES")

    # Session & Bootstrap User Provisioning Configuration
    session_ttl_minutes: int = Field(default=480, alias="SESSION_TTL_MINUTES")
    cookie_secure: bool = Field(default=False, alias="COOKIE_SECURE")
    initial_admin_tenant: str = Field(default="tenant-alpha", alias="INITIAL_ADMIN_TENANT")
    initial_admin_username: str = Field(default="admin", alias="INITIAL_ADMIN_USERNAME")
    initial_admin_email: str = Field(
        default="admin@graphrag.local", alias="INITIAL_ADMIN_EMAIL"
    )
    initial_admin_password: str = Field(
        default="Admin@GraphRAG2026!", alias="INITIAL_ADMIN_PASSWORD"
    )
    initial_analyst_password: str = Field(
        default="Analyst@GraphRAG2026!", alias="INITIAL_ANALYST_PASSWORD"
    )
    initial_viewer_password: str = Field(
        default="Viewer@GraphRAG2026!", alias="INITIAL_VIEWER_PASSWORD"
    )

    # API Key Auth Configuration (for programmatic CLI / service-to-service access)
    auth_api_keys: str = Field(
        default=(
            "dev-admin-key:user-admin:tenant-alpha:admin,"
            "dev-analyst-key:user-analyst:tenant-alpha:analyst,"
            "dev-viewer-key:user-viewer:tenant-alpha:viewer,"
            "dev-beta-key:user-beta:tenant-beta:analyst"
        ),
        alias="AUTH_API_KEYS",
    )
    default_dev_api_key: str = Field(default="dev-admin-key", alias="DEFAULT_DEV_API_KEY")
    require_auth: bool = Field(default=True, alias="REQUIRE_AUTH")

    # Model & Embedding Providers
    llm_provider: Literal["local", "openai", "ollama"] = Field(default="local", alias="LLM_PROVIDER")
    embedding_provider: Literal["local", "openai", "ollama"] = Field(
        default="local", alias="EMBEDDING_PROVIDER"
    )
    embedding_dim: int = Field(default=128, alias="EMBEDDING_DIM")

    # OpenAI settings
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_base_url: str = Field(default="https://api.openai.com/v1", alias="OPENAI_BASE_URL")
    openai_model: str = Field(default="gpt-4o-mini", alias="OPENAI_MODEL")
    openai_embedding_model: str = Field(
        default="text-embedding-3-small", alias="OPENAI_EMBEDDING_MODEL"
    )

    # Ollama settings
    ollama_base_url: str = Field(default="http://127.0.0.1:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="llama3.1:8b", alias="OLLAMA_MODEL")
    ollama_embedding_model: str = Field(
        default="nomic-embed-text", alias="OLLAMA_EMBEDDING_MODEL"
    )

    # Graph storage backend
    graph_backend: Literal["sqlite_networkx", "neo4j"] = Field(
        default="sqlite_networkx", alias="GRAPH_BACKEND"
    )
    neo4j_uri: str = Field(default="bolt://127.0.0.1:7687", alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", alias="NEO4J_USER")
    neo4j_password: str = Field(default="", alias="NEO4J_PASSWORD")

    # Retrieval & Chunking settings
    chunk_size_chars: int = Field(default=900, alias="CHUNK_SIZE_CHARS")
    chunk_overlap_chars: int = Field(default=150, alias="CHUNK_OVERLAP_CHARS")
    default_top_k_chunks: int = Field(default=6, alias="DEFAULT_TOP_K_CHUNKS")
    default_max_graph_hops: int = Field(default=2, alias="DEFAULT_MAX_GRAPH_HOPS")
    similarity_threshold: float = Field(default=0.08, alias="SIMILARITY_THRESHOLD")

    def parse_api_keys(self) -> Dict[str, Principal]:
        """Parse AUTH_API_KEYS into a map of api_key -> Principal."""
        mapping: Dict[str, Principal] = {}
        raw = self.auth_api_keys.strip()
        if not raw:
            return mapping
        for entry in raw.split(","):
            parts = [p.strip() for p in entry.strip().split(":")]
            if len(parts) == 4:
                key, user_id, tenant_id, role = parts
                if role in ("admin", "analyst", "viewer") and key:
                    mapping[key] = Principal(
                        user_id=user_id,
                        tenant_id=tenant_id,
                        username=user_id,
                        email=f"{user_id}@{tenant_id}.internal",
                        full_name=f"{user_id} ({role})",
                        role=role,  # type: ignore[arg-type]
                        auth_method="api_key",
                        allowed_doc_ids=["*"],
                    )
        return mapping

    def to_sanitized_dict(self) -> dict:
        """Return safe configuration dictionary with all secrets redacted."""
        return {
            "app_env": self.app_env,
            "llm_provider": self.llm_provider,
            "embedding_provider": self.embedding_provider,
            "embedding_dim": self.embedding_dim,
            "openai_base_url": self.openai_base_url,
            "openai_model": self.openai_model,
            "openai_embedding_model": self.openai_embedding_model,
            "openai_api_key_configured": bool(self.openai_api_key.strip()),
            "ollama_base_url": self.ollama_base_url,
            "ollama_model": self.ollama_model,
            "ollama_embedding_model": self.ollama_embedding_model,
            "graph_backend": self.graph_backend,
            "neo4j_uri": self.neo4j_uri,
            "neo4j_password_configured": bool(self.neo4j_password.strip()),
            "chunk_size_chars": self.chunk_size_chars,
            "chunk_overlap_chars": self.chunk_overlap_chars,
            "default_top_k_chunks": self.default_top_k_chunks,
            "default_max_graph_hops": self.default_max_graph_hops,
            "similarity_threshold": self.similarity_threshold,
            "max_upload_size_bytes": self.max_upload_size_bytes,
            "require_auth": self.require_auth,
            "session_ttl_minutes": self.session_ttl_minutes,
            "role_permission_matrix": ROLE_PERMISSION_MATRIX,
        }


settings = AppSettings()
