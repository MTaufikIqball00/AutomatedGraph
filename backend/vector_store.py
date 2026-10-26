"""Vector & lexical indexing with tenant isolation and configurable embedding providers."""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from typing import Dict, List, Optional, Tuple
import httpx
import numpy as np

from backend.config import settings
from backend.database import get_db_connection
from backend.schemas import ChunkRecord

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_-]{1,30}")
STOPWORDS = {
    "the", "and", "for", "that", "this", "with", "from", "are", "was", "were",
    "have", "has", "had", "not", "but", "what", "which", "when", "where", "who",
    "how", "why", "can", "will", "would", "should", "could", "into", "over",
    "under", "between", "through", "during", "before", "after", "above", "below",
    "about", "against", "among", "throughout", "despite", "towards", "upon",
}


def tokenize_for_search(text: str) -> List[str]:
    """Tokenize text into normalized content terms for BM25 and semantic hashing."""
    tokens = TOKEN_RE.findall(text.lower())
    return [t for t in tokens if t not in STOPWORDS and len(t) >= 2]


def compute_local_semantic_embedding(text: str, dim: int = 128) -> List[float]:
    """
    Deterministic multi-scale feature hashing embedding (unigrams + bigrams + char 4-grams).
    Produces L2-normalized dense vectors suitable for cosine similarity without external API keys.
    """
    vec = np.zeros(dim, dtype=np.float64)
    tokens = tokenize_for_search(text)
    if not tokens:
        return vec.tolist()

    # Unigrams (weight 1.0)
    for tok in tokens:
        h = int(hashlib.md5(tok.encode("utf-8")).hexdigest()[:8], 16)
        idx = h % dim
        sign = 1.0 if ((h >> 8) & 1) == 0 else -1.0
        vec[idx] += sign * 1.0

    # Bigrams (weight 1.25)
    for i in range(len(tokens) - 1):
        bg = f"{tokens[i]}_{tokens[i + 1]}"
        h = int(hashlib.md5(bg.encode("utf-8")).hexdigest()[:8], 16)
        idx = h % dim
        sign = 1.0 if ((h >> 8) & 1) == 0 else -1.0
        vec[idx] += sign * 1.25

    # Character stems / prefixes (weight 0.5) to capture morphological variants
    for tok in tokens:
        if len(tok) >= 5:
            stem = tok[:5]
            h = int(hashlib.md5(f"stem:{stem}".encode("utf-8")).hexdigest()[:8], 16)
            idx = h % dim
            sign = 1.0 if ((h >> 8) & 1) == 0 else -1.0
            vec[idx] += sign * 0.5

    norm = float(np.linalg.norm(vec))
    if norm > 1e-9:
        vec = vec / norm
    return [round(float(x), 6) for x in vec]


def embed_text(text: str) -> Tuple[List[float], str]:
    """
    Generate dense vector embedding for text using configured provider.
    Returns (embedding_vector, model_identifier).
    Falls back cleanly to local deterministic embeddings if external API fails.
    """
    provider = settings.embedding_provider
    dim = settings.embedding_dim

    if provider == "openai" and settings.openai_api_key:
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(
                    f"{settings.openai_base_url.rstrip('/')}/embeddings",
                    headers={"Authorization": f"Bearer {settings.openai_api_key}"},
                    json={"model": settings.openai_embedding_model, "input": text},
                )
                resp.raise_for_status()
                vec = resp.json()["data"][0]["embedding"]
                return vec, f"openai:{settings.openai_embedding_model}"
        except Exception:
            pass

    if provider == "ollama":
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(
                    f"{settings.ollama_base_url.rstrip('/')}/api/embeddings",
                    json={"model": settings.ollama_embedding_model, "prompt": text},
                )
                resp.raise_for_status()
                vec = resp.json().get("embedding")
                if isinstance(vec, list) and len(vec) > 0:
                    return vec, f"ollama:{settings.ollama_embedding_model}"
        except Exception:
            pass

    return compute_local_semantic_embedding(text, dim=dim), f"local:hash-{dim}d"


def cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """Compute cosine similarity between two vectors, safely handling dimension mismatches."""
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    a = np.asarray(vec_a, dtype=np.float64)
    b = np.asarray(vec_b, dtype=np.float64)
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denom < 1e-9:
        return 0.0
    return float(np.dot(a, b) / denom)


def index_chunks_vectors(
    tenant_id: str, chunks: List[ChunkRecord], db_path: Optional[str] = None
) -> int:
    """Compute and store embeddings for a batch of chunks in SQLite."""
    updated = 0
    with get_db_connection(db_path) as conn:
        for chk in chunks:
            vec, model_name = embed_text(f"{chk.section_title}\n{chk.text}")
            conn.execute(
                """
                UPDATE chunks
                SET embedding_json = ?, embedding_model = ?
                WHERE tenant_id = ? AND chunk_id = ?
                """,
                (json.dumps(vec), model_name, tenant_id, chk.chunk_id),
            )
            updated += 1
    return updated


def search_chunks_hybrid_vector_bm25(
    tenant_id: str,
    query: str,
    top_k: int = 6,
    doc_ids: Optional[List[str]] = None,
    vector_only: bool = False,
    db_path: Optional[str] = None,
) -> List[Dict[str, object]]:
    """
    Search tenant-scoped chunks using dense vector cosine similarity and BM25 lexical scoring.
    If vector_only=True, ranks strictly by dense vector similarity (plus lightweight term tie-breaking)
    to serve as a clean Conventional Vector RAG baseline.
    """
    if doc_ids is not None and len(doc_ids) == 0:
        return []

    q_vec, q_model = embed_text(query)
    q_tokens = tokenize_for_search(query)

    with get_db_connection(db_path) as conn:
        params: List[object] = [tenant_id]
        doc_filter_sql = ""
        if doc_ids is not None:
            placeholders = ",".join("?" for _ in doc_ids)
            doc_filter_sql = f" AND c.doc_id IN ({placeholders})"
            params.extend(doc_ids)

        rows = conn.execute(
            f"""
            SELECT c.chunk_id, c.doc_id, c.chunk_index, c.page_number, c.section_title,
                   c.text, c.char_start, c.char_end, c.token_count,
                   c.embedding_json, c.embedding_model, d.filename
            FROM chunks c
            JOIN documents d ON d.tenant_id = c.tenant_id AND d.doc_id = c.doc_id
            WHERE c.tenant_id = ? AND d.status = 'completed'{doc_filter_sql}
            """,
            params,
        ).fetchall()

    if not rows:
        return []

    # Prepare BM25 statistics across candidate chunks
    doc_tokens_list: List[List[str]] = []
    df_counts: Counter[str] = Counter()
    for r in rows:
        toks = tokenize_for_search(f"{r['section_title']} {r['text']}")
        doc_tokens_list.append(toks)
        for ut in set(toks):
            df_counts[ut] += 1

    n_docs = len(rows)
    avgdl = max(1.0, sum(len(t) for t in doc_tokens_list) / n_docs)
    k1 = 1.5
    b = 0.75

    scored_results: List[Dict[str, object]] = []
    for idx, r in enumerate(rows):
        emb_raw = r["embedding_json"]
        c_vec: List[float] = json.loads(emb_raw) if emb_raw else []
        if not c_vec or len(c_vec) != len(q_vec):
            c_vec = compute_local_semantic_embedding(
                f"{r['section_title']}\n{r['text']}", dim=len(q_vec)
            )
        vec_sim = max(0.0, cosine_similarity(q_vec, c_vec))

        # Compute BM25 score
        d_toks = doc_tokens_list[idx]
        tf_map = Counter(d_toks)
        dl = len(d_toks)
        bm25_raw = 0.0
        matched_terms = 0
        for qt in set(q_tokens):
            tf = tf_map.get(qt, 0)
            if tf > 0:
                matched_terms += 1
                df = df_counts.get(qt, 0)
                idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
                denom = tf + k1 * (1.0 - b + b * (dl / avgdl))
                bm25_raw += idf * ((tf * (k1 + 1.0)) / denom)

        # Normalize BM25 into [0, 1] range
        bm25_norm = bm25_raw / (bm25_raw + 3.0) if bm25_raw > 0 else 0.0

        if vector_only:
            combined_score = round(0.85 * vec_sim + 0.15 * bm25_norm, 4)
            source_label = "vector_search"
        else:
            combined_score = round(0.55 * vec_sim + 0.45 * bm25_norm, 4)
            source_label = "vector+bm25"

        scored_results.append(
            {
                "chunk_id": r["chunk_id"],
                "doc_id": r["doc_id"],
                "filename": r["filename"],
                "chunk_index": r["chunk_index"],
                "page_number": r["page_number"],
                "section_title": r["section_title"],
                "text": r["text"],
                "char_start": r["char_start"],
                "char_end": r["char_end"],
                "vector_score": round(vec_sim, 4),
                "bm25_score": round(bm25_norm, 4),
                "matched_query_terms": matched_terms,
                "relevance_score": combined_score,
                "retrieval_source": source_label,
            }
        )

    scored_results.sort(key=lambda x: float(x["relevance_score"]), reverse=True)  # type: ignore[arg-type]
    return scored_results[:top_k]
