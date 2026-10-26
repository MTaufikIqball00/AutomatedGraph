"""End-to-end ingestion, extraction, graph construction, and vector indexing pipeline with job tracking."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.database import get_db_connection
from backend.extraction import extract_from_chunk
from backend.graph_store import KnowledgeGraphStore, utc_now_iso
from backend.ingestion import (
    compute_doc_id,
    compute_sha256,
    extract_text_from_file,
    preprocess_and_chunk_document,
)
from backend.schemas import ChunkExtractionResult, JobStatus
from backend.vector_store import index_chunks_vectors


def create_job_record(
    tenant_id: str,
    job_type: str,
    doc_id: Optional[str] = None,
    db_path: Optional[str] = None,
) -> str:
    """Create a persistent pipeline job record in SQLite."""
    now = utc_now_iso()
    raw = f"{tenant_id}::{job_type}::{doc_id}::{now}::{time.time_ns()}"
    job_id = "job-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO jobs (
                job_id, tenant_id, doc_id, job_type, status, stage,
                progress_pct, details_json, started_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                tenant_id,
                doc_id,
                job_type,
                JobStatus.RUNNING.value,
                "initializing",
                5,
                json.dumps({}),
                now,
            ),
        )
    return job_id


def update_job_record(
    tenant_id: str,
    job_id: str,
    status: str,
    stage: str,
    progress_pct: int,
    details: Optional[Dict[str, Any]] = None,
    error_message: Optional[str] = None,
    finished: bool = False,
    db_path: Optional[str] = None,
) -> None:
    """Update job progress, stage, or error state."""
    finished_at = utc_now_iso() if finished else None
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            UPDATE jobs
            SET status = ?, stage = ?, progress_pct = ?,
                details_json = COALESCE(?, details_json),
                error_message = COALESCE(?, error_message),
                finished_at = COALESCE(?, finished_at)
            WHERE tenant_id = ? AND job_id = ?
            """,
            (
                status,
                stage,
                progress_pct,
                json.dumps(details) if details is not None else None,
                error_message,
                finished_at,
                tenant_id,
                job_id,
            ),
        )


def ingest_and_index_document(
    tenant_id: str,
    filename: str,
    raw_bytes: bytes,
    mime_type: str = "text/markdown",
    is_synthetic_demo: bool = False,
    owner_user_id: str = "user-admin",
    visibility: str = "tenant",
    allowed_roles: Optional[List[str]] = None,
    allowed_user_ids: Optional[List[str]] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute the complete 7-stage ingestion & indexing pipeline for a document:
    1. Parse & extract text + metadata
    2. Structure-aware preprocessing & deterministic chunking
    3. Schema-validated entity & relationship extraction
    4. Entity resolution (canonicalization + uncertain match tracking)
    5. Idempotent knowledge graph construction & community detection
    6. Dense vector & BM25 indexing
    7. Job & telemetry recording
    """
    t0 = time.perf_counter()
    doc_id = compute_doc_id(tenant_id, filename)
    sha256 = compute_sha256(raw_bytes)
    now = utc_now_iso()
    job_id = create_job_record(tenant_id, "document_ingestion", doc_id=doc_id, db_path=db_path)

    roles_json = json.dumps(allowed_roles if allowed_roles is not None else ["admin", "analyst", "viewer"])
    users_json = json.dumps(allowed_user_ids if allowed_user_ids is not None else [])

    # Create or update document record as 'indexing'
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO documents (
                doc_id, tenant_id, filename, mime_type, file_size, sha256,
                status, is_synthetic_demo, owner_user_id, visibility,
                allowed_roles_json, allowed_user_ids_json,
                error_message, metadata_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '{}', ?, ?)
            ON CONFLICT(tenant_id, doc_id) DO UPDATE SET
                mime_type = excluded.mime_type,
                file_size = excluded.file_size,
                sha256 = excluded.sha256,
                status = 'indexing',
                is_synthetic_demo = excluded.is_synthetic_demo,
                owner_user_id = excluded.owner_user_id,
                visibility = excluded.visibility,
                allowed_roles_json = excluded.allowed_roles_json,
                allowed_user_ids_json = excluded.allowed_user_ids_json,
                error_message = NULL,
                updated_at = excluded.updated_at
            """,
            (
                doc_id,
                tenant_id,
                filename,
                mime_type,
                len(raw_bytes),
                sha256,
                "indexing",
                1 if is_synthetic_demo else 0,
                owner_user_id,
                visibility,
                roles_json,
                users_json,
                now,
                now,
            ),
        )

    try:
        # Stage 1: Parse text
        update_job_record(tenant_id, job_id, JobStatus.RUNNING.value, "parsing_document", 15, db_path=db_path)
        text, doc_metadata = extract_text_from_file(filename, raw_bytes)
        if is_synthetic_demo:
            doc_metadata["synthetic_demo_fixture"] = True

        # Stage 2: Preprocess & chunk
        update_job_record(tenant_id, job_id, JobStatus.RUNNING.value, "preprocessing_chunks", 30, db_path=db_path)
        chunks = preprocess_and_chunk_document(
            doc_id=doc_id,
            tenant_id=tenant_id,
            raw_text=text,
            chunk_size_chars=settings.chunk_size_chars,
            chunk_overlap_chars=settings.chunk_overlap_chars,
        )

        # Stage 3: Entity & Relationship Extraction
        update_job_record(tenant_id, job_id, JobStatus.RUNNING.value, "extracting_entities_relationships", 55, db_path=db_path)
        extractions: List[ChunkExtractionResult] = []
        extraction_warnings: List[str] = []
        for chk in chunks:
            ext_res = extract_from_chunk(chk)
            extractions.append(ext_res)
            extraction_warnings.extend(ext_res.warnings)

        # Stage 4 & 5: Entity Resolution, Graph Construction & Community Detection
        update_job_record(tenant_id, job_id, JobStatus.RUNNING.value, "building_knowledge_graph", 75, db_path=db_path)
        graph_store = KnowledgeGraphStore(db_path=db_path)
        graph_stats = graph_store.upsert_document_graph_artifacts(
            tenant_id=tenant_id,
            doc_id=doc_id,
            chunks=chunks,
            extractions=extractions,
        )

        # Stage 6: Vector Indexing
        update_job_record(tenant_id, job_id, JobStatus.RUNNING.value, "indexing_vectors", 90, db_path=db_path)
        embedded_count = index_chunks_vectors(tenant_id=tenant_id, chunks=chunks, db_path=db_path)

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        doc_metadata.update(
            {
                "indexing_latency_ms": elapsed_ms,
                "embedded_chunks": embedded_count,
                "extraction_warnings": extraction_warnings[:10],
                **graph_stats,
            }
        )

        with get_db_connection(db_path) as conn:
            conn.execute(
                """
                UPDATE documents
                SET status = 'completed', metadata_json = ?, updated_at = ?
                WHERE tenant_id = ? AND doc_id = ?
                """,
                (json.dumps(doc_metadata), utc_now_iso(), tenant_id, doc_id),
            )

        update_job_record(
            tenant_id=tenant_id,
            job_id=job_id,
            status=JobStatus.COMPLETED.value,
            stage="completed",
            progress_pct=100,
            details=doc_metadata,
            finished=True,
            db_path=db_path,
        )

        return {
            "job_id": job_id,
            "doc_id": doc_id,
            "filename": filename,
            "status": "completed",
            "is_synthetic_demo": is_synthetic_demo,
            "latency_ms": elapsed_ms,
            **graph_stats,
        }

    except Exception as exc:
        err_msg = str(exc)
        with get_db_connection(db_path) as conn:
            conn.execute(
                """
                UPDATE documents
                SET status = 'failed', error_message = ?, updated_at = ?
                WHERE tenant_id = ? AND doc_id = ?
                """,
                (err_msg, utc_now_iso(), tenant_id, doc_id),
            )
        update_job_record(
            tenant_id=tenant_id,
            job_id=job_id,
            status=JobStatus.FAILED.value,
            stage="failed",
            progress_pct=100,
            error_message=err_msg,
            finished=True,
            db_path=db_path,
        )
        raise
