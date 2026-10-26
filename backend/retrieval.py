"""Query routing and hybrid retrieval combining vector, BM25, graph traversal, and communities."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

from backend.database import get_db_connection
from backend.graph_store import KnowledgeGraphStore
from backend.schemas import CitationItem, CommunityView, GraphPathCitation
from backend.vector_store import search_chunks_hybrid_vector_bm25

GLOBAL_QUERY_CUES = re.compile(
    r"\b(overall|summary|summarize|themes?|trends?|across\s+all\s+documents|communities|clusters|high-level|landscape|main\s+risks|executive\s+overview|global)\b",
    re.IGNORECASE,
)

MULTI_HOP_CUES = re.compile(
    r"\b(how\s+did|chain\s+of|indirectly|downstream|upstream|root\s+cause|cascade|cascading|connect|relationship\s+between|path\s+from|impact\s+on|which\s+regulatory|who\s+operates)\b",
    re.IGNORECASE,
)


def route_query_strategy(
    question: str,
    requested_strategy: Literal["auto", "local", "global", "hybrid", "vector_only"] = "auto",
) -> str:
    """
    Route a user question to the optimal retrieval strategy:
    - 'vector_only': Baseline conventional RAG (dense vector + slight lexical tie-breaker, zero graph).
    - 'global': Community-first global thematic/trend aggregation + supporting chunks.
    - 'local': Entity-centric multi-hop graph traversal + chunk provenance.
    - 'hybrid': Combines local multi-hop graph paths, community summaries, and hybrid vector+BM25 chunks.
    """
    if requested_strategy != "auto":
        return requested_strategy

    is_global = bool(GLOBAL_QUERY_CUES.search(question))
    is_multihop = bool(MULTI_HOP_CUES.search(question))

    if is_global and not is_multihop:
        return "global"
    if is_multihop and not is_global:
        return "hybrid"
    if is_global and is_multihop:
        return "hybrid"
    return "hybrid"


def execute_hybrid_retrieval(
    tenant_id: str,
    question: str,
    strategy: Literal["auto", "local", "global", "hybrid", "vector_only"] = "auto",
    top_k_chunks: int = 6,
    max_hops: int = 2,
    include_inferred: bool = True,
    doc_ids: Optional[List[str]] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute the selected retrieval strategy scoped strictly to `tenant_id`.
    Returns citations, graph_paths, communities_used, and human-readable explanation.
    """
    routed = route_query_strategy(question, strategy)
    graph_store = KnowledgeGraphStore(db_path=db_path)

    # 1. Baseline Vector-Only mode (no graph paths or community expansion)
    if routed == "vector_only":
        chunk_hits = search_chunks_hybrid_vector_bm25(
            tenant_id=tenant_id,
            query=question,
            top_k=top_k_chunks,
            doc_ids=doc_ids,
            vector_only=True,
            db_path=db_path,
        )
        citations = [
            CitationItem(
                citation_id=f"cit-{idx:02d}",
                doc_id=str(c["doc_id"]),
                filename=str(c["filename"]),
                chunk_id=str(c["chunk_id"]),
                page_number=int(c["page_number"]),  # type: ignore[arg-type]
                section_title=str(c["section_title"]),
                evidence_quote=str(c["text"])[:450],
                relevance_score=float(c["relevance_score"]),  # type: ignore[arg-type]
                retrieval_source="vector_search",
            )
            for idx, c in enumerate(chunk_hits, start=1)
            if float(c["relevance_score"]) >= 0.08  # type: ignore[arg-type]
        ]
        return {
            "routed_strategy": "vector_only",
            "citations": citations,
            "graph_paths": [],
            "communities_used": [],
            "retrieval_explanation": (
                f"Executed baseline vector_only retrieval: ranked {len(citations)} chunk(s) "
                "by semantic vector similarity without knowledge graph traversal or community summaries."
            ),
        }

    # 2. Graph-enabled retrieval (local, global, hybrid)
    graph_paths: List[GraphPathCitation] = []
    graph_chunk_ids: Set[str] = set()
    communities_used: List[CommunityView] = []

    if routed in ("local", "hybrid", "global"):
        graph_paths, graph_chunk_ids = graph_store.retrieve_entity_paths_and_context(
            tenant_id=tenant_id,
            query=question,
            max_hops=max_hops,
            include_inferred=include_inferred,
            doc_ids=doc_ids,
        )

    if routed in ("global", "hybrid"):
        all_comms = graph_store.get_communities(tenant_id, authorized_doc_ids=doc_ids)
        communities_used = all_comms[:5]

    # 3. Hybrid Vector + BM25 search
    chunk_hits = search_chunks_hybrid_vector_bm25(
        tenant_id=tenant_id,
        query=question,
        top_k=top_k_chunks,
        doc_ids=doc_ids,
        vector_only=False,
        db_path=db_path,
    )

    seen_chunk_ids: Set[str] = set()
    merged_chunks: List[Dict[str, object]] = []

    for c in chunk_hits:
        cid = str(c["chunk_id"])
        boost = 0.18 if cid in graph_chunk_ids else 0.0
        c["relevance_score"] = round(min(1.0, float(c["relevance_score"]) + boost), 4)  # type: ignore[arg-type]
        if cid in graph_chunk_ids:
            c["retrieval_source"] = "hybrid_vector+bm25+graph"
        if float(c["relevance_score"]) >= 0.08 or int(c.get("matched_query_terms", 0)) >= 1:  # type: ignore[arg-type]
            seen_chunk_ids.add(cid)
            merged_chunks.append(c)

    # 4. Fetch any multi-hop provenance chunks discovered ONLY via graph traversal
    # strictly within the caller's authorized doc_ids scope!
    missing_graph_chunks = [cid for cid in graph_chunk_ids if cid not in seen_chunk_ids]
    if missing_graph_chunks and (doc_ids is None or len(doc_ids) > 0):
        with get_db_connection(db_path) as conn:
            placeholders = ",".join("?" for _ in missing_graph_chunks)
            params: List[object] = [tenant_id, *missing_graph_chunks]
            doc_acl_sql = ""
            if doc_ids is not None:
                doc_placeholders = ",".join("?" for _ in doc_ids)
                doc_acl_sql = f" AND c.doc_id IN ({doc_placeholders})"
                params.extend(doc_ids)
            rows = conn.execute(
                f"""
                SELECT c.chunk_id, c.doc_id, c.page_number, c.section_title, c.text, d.filename
                FROM chunks c
                JOIN documents d ON d.tenant_id = c.tenant_id AND d.doc_id = c.doc_id
                WHERE c.tenant_id = ? AND c.chunk_id IN ({placeholders}){doc_acl_sql}
                """,
                params,
            ).fetchall()
            for r in rows:
                merged_chunks.append(
                    {
                        "chunk_id": r["chunk_id"],
                        "doc_id": r["doc_id"],
                        "filename": r["filename"],
                        "page_number": r["page_number"],
                        "section_title": r["section_title"],
                        "text": r["text"],
                        "relevance_score": 0.78,
                        "retrieval_source": "graph_multi_hop_provenance",
                    }
                )

    merged_chunks.sort(key=lambda x: float(x["relevance_score"]), reverse=True)  # type: ignore[arg-type]
    merged_chunks = merged_chunks[: top_k_chunks + 2]

    citations = [
        CitationItem(
            citation_id=f"cit-{idx:02d}",
            doc_id=str(c["doc_id"]),
            filename=str(c["filename"]),
            chunk_id=str(c["chunk_id"]),
            page_number=int(c["page_number"]),  # type: ignore[arg-type]
            section_title=str(c["section_title"]),
            evidence_quote=str(c["text"])[:480],
            relevance_score=float(c["relevance_score"]),  # type: ignore[arg-type]
            retrieval_source=str(c["retrieval_source"]),
        )
        for idx, c in enumerate(merged_chunks, start=1)
    ]

    explanation = (
        f"Routed to '{routed}' strategy: retrieved {len(citations)} evidence chunk(s) "
        f"(including {len(missing_graph_chunks)} multi-hop graph-linked chunk(s)), "
        f"{len(graph_paths)} knowledge graph path(s) (max_hops={max_hops}), and "
        f"{len(communities_used)} community summary cluster(s)."
    )

    return {
        "routed_strategy": routed,
        "citations": citations,
        "graph_paths": graph_paths,
        "communities_used": communities_used,
        "retrieval_explanation": explanation,
    }
