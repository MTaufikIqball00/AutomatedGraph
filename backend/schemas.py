"""Pydantic v2 schemas for the Automated GraphRAG system."""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


class EntityType(str, Enum):
    """Allowed node entity types in the knowledge graph."""
    ORGANIZATION = "ORGANIZATION"
    PERSON = "PERSON"
    SYSTEM = "SYSTEM"
    EVENT = "EVENT"
    LOCATION = "LOCATION"
    METRIC = "METRIC"
    POLICY = "POLICY"
    TECHNOLOGY = "TECHNOLOGY"
    CONCEPT = "CONCEPT"
    DATE = "DATE"


class RelationshipType(str, Enum):
    """Allowlisted typed relationships between entities."""
    DEPENDS_ON = "DEPENDS_ON"
    CAUSED_BY = "CAUSED_BY"
    OPERATES = "OPERATES"
    ACQUIRED = "ACQUIRED"
    PARTNERED_WITH = "PARTNERED_WITH"
    REGULATED_BY = "REGULATED_BY"
    LOCATED_IN = "LOCATED_IN"
    DEVELOPED_BY = "DEVELOPED_BY"
    IMPACTS = "IMPACTS"
    REPORTED_METRIC = "REPORTED_METRIC"
    SUCCEEDED_BY = "SUCCEEDED_BY"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"


class JobStatus(str, Enum):
    """Indexing and pipeline job lifecycle states."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class LoginRequest(BaseModel):
    """User login credentials payload."""
    identifier: str = Field(..., min_length=2, max_length=150, description="Username or email address")
    password: str = Field(..., min_length=4, max_length=200)


class PasswordChangeRequest(BaseModel):
    """Authenticated self-service password change request."""
    current_password: str = Field(..., min_length=4, max_length=200)
    new_password: str = Field(..., min_length=8, max_length=200)


class UserCreateRequest(BaseModel):
    """Admin payload to create/provision a new user account."""
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(..., min_length=5, max_length=150, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    full_name: str = Field(..., min_length=2, max_length=120)
    password: str = Field(..., min_length=8, max_length=200)
    role: Literal["admin", "analyst", "viewer"] = "viewer"
    is_active: bool = True
    allowed_doc_ids: List[str] = Field(default_factory=lambda: ["*"])


class UserUpdateRequest(BaseModel):
    """Admin payload to update user profile, role, active state, document ACL scope, or password."""
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    email: Optional[str] = Field(default=None, min_length=5, max_length=150, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: Optional[Literal["admin", "analyst", "viewer"]] = None
    is_active: Optional[bool] = None
    allowed_doc_ids: Optional[List[str]] = None
    new_password: Optional[str] = Field(default=None, min_length=8, max_length=200)


class DocumentACLUpdateRequest(BaseModel):
    """Update document-level visibility and role/user access control lists."""
    visibility: Literal["tenant", "restricted"] = "tenant"
    allowed_roles: List[Literal["admin", "analyst", "viewer"]] = Field(
        default_factory=lambda: ["admin", "analyst", "viewer"]
    )
    allowed_user_ids: List[str] = Field(default_factory=list)


class ChunkRecord(BaseModel):
    """A structure-aware preprocessed document chunk with stable ID."""
    chunk_id: str
    doc_id: str
    tenant_id: str
    chunk_index: int
    page_number: int = 1
    section_title: str = "Root"
    text: str
    char_start: int
    char_end: int
    token_count: int


class ExtractedEntity(BaseModel):
    """Schema-validated entity extracted from a chunk."""
    name: str = Field(..., min_length=2, max_length=200)
    entity_type: EntityType
    aliases: List[str] = Field(default_factory=list)
    description: str = Field(default="", max_length=1000)
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    evidence_quote: str = Field(..., min_length=2, max_length=600)
    char_start: int = Field(default=0, ge=0)
    char_end: int = Field(default=0, ge=0)

    @field_validator("name")
    @classmethod
    def clean_name(cls, v: str) -> str:
        cleaned = " ".join(v.strip().split())
        if len(cleaned) < 2:
            raise ValueError("Entity name must be at least 2 non-whitespace characters.")
        return cleaned


class ExtractedRelationship(BaseModel):
    """Schema-validated typed relationship between two extracted entities."""
    source_entity: str = Field(..., min_length=2, max_length=200)
    target_entity: str = Field(..., min_length=2, max_length=200)
    relationship_type: RelationshipType
    is_inferred: bool = Field(
        default=False,
        description="False if explicitly stated in text; True if inferred across sentences/context.",
    )
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    evidence_quote: str = Field(..., min_length=3, max_length=600)
    char_start: int = Field(default=0, ge=0)
    char_end: int = Field(default=0, ge=0)
    temporal_marker: Optional[str] = Field(default=None, max_length=100)


class ChunkExtractionResult(BaseModel):
    """Validated output from extracting entities and relationships from one chunk."""
    chunk_id: str
    doc_id: str
    entities: List[ExtractedEntity] = Field(default_factory=list)
    relationships: List[ExtractedRelationship] = Field(default_factory=list)
    extraction_method: str = "local_deterministic"
    warnings: List[str] = Field(default_factory=list)


class UncertainEntityMatch(BaseModel):
    """Tracked uncertain entity resolution candidate pair that was NOT automatically merged."""
    match_id: str
    tenant_id: str
    entity_a_id: str
    entity_a_name: str
    entity_b_id: str
    entity_b_name: str
    entity_type: EntityType
    similarity_score: float
    reason: str
    doc_id: str
    created_at: str


class DocumentSummary(BaseModel):
    """Document metadata and ingestion summary returned by the API."""
    doc_id: str
    tenant_id: str
    filename: str
    mime_type: str
    file_size: int
    sha256: str
    status: str
    is_synthetic_demo: bool = False
    owner_user_id: str = "user-admin"
    visibility: str = "tenant"
    allowed_roles: List[str] = Field(default_factory=lambda: ["admin", "analyst", "viewer"])
    allowed_user_ids: List[str] = Field(default_factory=list)
    chunk_count: int = 0
    entity_count: int = 0
    relationship_count: int = 0
    error_message: Optional[str] = None
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphNodeView(BaseModel):
    """Knowledge graph node representation for the explorer and retrieval responses."""
    entity_id: str
    canonical_name: str
    entity_type: EntityType
    aliases: List[str] = Field(default_factory=list)
    description: str = ""
    confidence: float = 0.85
    degree: int = 0
    community_id: Optional[str] = None
    document_ids: List[str] = Field(default_factory=list)
    mentions: List[Dict[str, Any]] = Field(default_factory=list)


class GraphEdgeView(BaseModel):
    """Knowledge graph edge representation with full provenance."""
    edge_id: str
    source_id: str
    source_name: str
    target_id: str
    target_name: str
    relationship_type: RelationshipType
    is_inferred: bool
    confidence: float
    doc_id: str
    filename: str = ""
    chunk_id: str
    evidence_quote: str
    char_start: int = 0
    char_end: int = 0
    temporal_marker: Optional[str] = None


class CommunityView(BaseModel):
    """Detected graph community and synthesized global summary."""
    community_id: str
    tenant_id: str
    level: int = 0
    title: str
    summary: str
    entity_count: int
    entity_names: List[str]
    relationship_count: int
    dominant_types: List[str]
    source_doc_ids: List[str]
    updated_at: str


class CitationItem(BaseModel):
    """Traceable text citation backing a generated response."""
    citation_id: str
    doc_id: str
    filename: str
    chunk_id: str
    page_number: int
    section_title: str
    evidence_quote: str
    relevance_score: float
    retrieval_source: str


class GraphPathCitation(BaseModel):
    """Traceable knowledge graph path backing a generated response."""
    path_id: str
    nodes: List[str]
    edges: List[Dict[str, Any]]
    path_text: str
    has_inferred_edge: bool
    min_confidence: float
    source_doc_ids: List[str]


class QueryRequest(BaseModel):
    """Request payload for querying the Automated GraphRAG workspace."""
    question: str = Field(..., min_length=3, max_length=2000)
    strategy: Literal["auto", "local", "global", "hybrid", "vector_only"] = "auto"
    top_k_chunks: int = Field(default=6, ge=1, le=20)
    max_hops: int = Field(default=2, ge=1, le=4)
    include_inferred: bool = True
    doc_ids: Optional[List[str]] = None


class QueryResponse(BaseModel):
    """Evidence-grounded response with citations, graph paths, and telemetry."""
    query_id: str
    question: str
    routed_strategy: str
    answer: str
    abstained: bool
    abstention_reason: Optional[str] = None
    contradictions_detected: List[str] = Field(default_factory=list)
    prompt_injection_warnings: List[str] = Field(default_factory=list)
    citations: List[CitationItem] = Field(default_factory=list)
    graph_paths: List[GraphPathCitation] = Field(default_factory=list)
    communities_used: List[CommunityView] = Field(default_factory=list)
    retrieval_explanation: str
    latency_ms: float
    metrics: Dict[str, Any] = Field(default_factory=dict)


class ConfigUpdateRequest(BaseModel):
    """Authorized runtime configuration update payload."""
    llm_provider: Optional[Literal["local", "openai", "ollama"]] = None
    embedding_provider: Optional[Literal["local", "openai", "ollama"]] = None
    openai_model: Optional[str] = None
    ollama_base_url: Optional[str] = None
    ollama_model: Optional[str] = None
    default_top_k_chunks: Optional[int] = Field(default=None, ge=1, le=20)
    default_max_graph_hops: Optional[int] = Field(default=None, ge=1, le=4)
    similarity_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    chunk_size_chars: Optional[int] = Field(default=None, ge=200, le=4000)
    chunk_overlap_chars: Optional[int] = Field(default=None, ge=0, le=1000)
