"""Knowledge graph construction, idempotency, community detection, and multi-hop traversal."""
from __future__ import annotations

import hashlib
import itertools
import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from backend.database import get_db_connection, get_db_path
from backend.entity_resolution import (
    EntityResolver,
    compute_pair_signature,
    normalize_entity_key,
)
from backend.schemas import (
    ChunkExtractionResult,
    ChunkRecord,
    CommunityView,
    EntityType,
    GraphEdgeView,
    GraphNodeView,
    GraphPathCitation,
    RelationshipType,
)


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def compute_edge_id(
    tenant_id: str,
    source_id: str,
    target_id: str,
    rel_type: str,
    chunk_id: str,
) -> str:
    """Compute a deterministic, idempotent edge ID scoped to tenant, endpoints, type, and chunk."""
    raw = f"{tenant_id}::{source_id}::{rel_type}::{target_id}::{chunk_id}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"edg-{digest}"


def compute_mention_id(
    tenant_id: str, entity_id: str, chunk_id: str, char_start: int
) -> str:
    """Compute a deterministic mention ID."""
    raw = f"{tenant_id}::{entity_id}::{chunk_id}::{char_start}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:14]
    return f"mnt-{digest}"


class KnowledgeGraphStore:
    """
    Transactional SQLite + NetworkX Knowledge Graph Store.
    - Guarantees idempotent entity, mention, and relationship persistence.
    - Tracks full provenance (doc_id, chunk_id, evidence_quote, char_start/end, is_inferred).
    - Supports clean document updates and cascade deletions (removing orphaned entities while
      preserving shared entities still referenced by other documents).
    - Builds communities using NetworkX greedy modularity and generates global community summaries.
    """

    _GRAPH_CACHE: Dict[Tuple[str, str, Optional[Tuple[str, ...]]], Tuple[int, nx.MultiDiGraph]] = {}
    _WRITE_VERSIONS: Dict[Tuple[str, str], int] = {}
    _MAX_CACHE_ENTRIES = 32

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path

    def _resolved_db_key(self) -> str:
        return str(get_db_path(self.db_path))

    def _invalidate_graph_cache(self, tenant_id: str) -> None:
        db_key = self._resolved_db_key()
        vk = (db_key, tenant_id)
        self._WRITE_VERSIONS[vk] = self._WRITE_VERSIONS.get(vk, 0) + 1
        stale_keys = [k for k in self._GRAPH_CACHE if k[0] == db_key and k[1] == tenant_id]
        for k in stale_keys:
            self._GRAPH_CACHE.pop(k, None)

    def load_resolution_decisions(self, tenant_id: str) -> Dict[str, Dict[str, object]]:
        """Load persisted entity resolution decisions (`merged` / `kept_distinct`) for a tenant."""
        decisions: Dict[str, Dict[str, object]] = {}
        try:
            with get_db_connection(self.db_path) as conn:
                rows = conn.execute(
                    """
                    SELECT pair_signature, entity_type, key_a, key_b, decision, canonical_key, decided_by, decided_at
                    FROM entity_resolution_decisions
                    WHERE tenant_id = ?
                    """,
                    (tenant_id,),
                ).fetchall()
            for r in rows:
                decisions[str(r["pair_signature"])] = dict(r)
        except Exception:
            return {}
        return decisions

    def load_existing_entities(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Load all existing entities for a tenant to initialize EntityResolver."""
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT entity_id, tenant_id, canonical_name, normalized_key,
                       entity_type, aliases_json, description, confidence, community_id
                FROM entities
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            ).fetchall()
        results: List[Dict[str, Any]] = []
        for r in rows:
            results.append(
                {
                    "entity_id": r["entity_id"],
                    "tenant_id": r["tenant_id"],
                    "canonical_name": r["canonical_name"],
                    "normalized_key": r["normalized_key"],
                    "entity_type": r["entity_type"],
                    "aliases": json.loads(r["aliases_json"] or "[]"),
                    "description": r["description"],
                    "confidence": float(r["confidence"]),
                    "community_id": r["community_id"],
                }
            )
        return results

    def _prune_orphaned_entities_and_matches(
        self, conn: sqlite3.Connection, tenant_id: str
    ) -> None:
        """Delete orphaned entities with zero mentions and any pending matches referencing missing entities."""
        conn.execute(
            """
            DELETE FROM entities
            WHERE tenant_id = ?
              AND entity_id NOT IN (
                  SELECT DISTINCT entity_id FROM entity_mentions WHERE tenant_id = ?
              )
            """,
            (tenant_id, tenant_id),
        )
        conn.execute(
            """
            DELETE FROM uncertain_matches
            WHERE tenant_id = ?
              AND status = 'pending'
              AND (
                  entity_a_id = entity_b_id
                  OR entity_a_id NOT IN (SELECT entity_id FROM entities WHERE tenant_id = ?)
                  OR entity_b_id NOT IN (SELECT entity_id FROM entities WHERE tenant_id = ?)
              )
            """,
            (tenant_id, tenant_id, tenant_id),
        )

    def upsert_document_graph_artifacts(
        self,
        tenant_id: str,
        doc_id: str,
        chunks: List[ChunkRecord],
        extractions: List[ChunkExtractionResult],
    ) -> Dict[str, int]:
        """
        Idempotently persist chunks, resolved entities, entity mentions, relationships,
        and uncertain entity matches inside an ACID transaction, then refresh communities.
        """
        now = utc_now_iso()
        existing_entities = self.load_existing_entities(tenant_id)
        resolution_decisions = self.load_resolution_decisions(tenant_id)
        resolver = EntityResolver(
            existing_entities=existing_entities,
            tenant_id=tenant_id,
            resolution_decisions=resolution_decisions,
        )

        entity_Count_for_doc = 0
        relationship_count_for_doc = 0
        uncertain_count_for_doc = 0

        with get_db_connection(self.db_path) as conn:
            # Remove prior chunks/mentions/edges for idempotent re-indexing; pending uncertain
            # matches are pruned below only if referenced entities become orphaned.
            conn.execute(
                "DELETE FROM relationships WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            )
            conn.execute(
                "DELETE FROM entity_mentions WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            )
            conn.execute(
                "DELETE FROM chunks WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            )

            # 1. Insert chunks
            for chk in chunks:
                conn.execute(
                    """
                    INSERT INTO chunks (
                        chunk_id, doc_id, tenant_id, chunk_index, page_number,
                        section_title, text, char_start, char_end, token_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        chk.chunk_id,
                        chk.doc_id,
                        tenant_id,
                        chk.chunk_index,
                        chk.page_number,
                        chk.section_title,
                        chk.text,
                        chk.char_start,
                        chk.char_end,
                        chk.token_count,
                    ),
                )

            doc_entity_ids: Set[str] = set()

            # 2. Resolve and upsert entities + mentions + relationships per chunk
            for ext in extractions:
                chunk_name_to_id: Dict[str, str] = {}

                for ent in ext.entities:
                    resolved, uncertain_list = resolver.resolve(ent, doc_id=doc_id)
                    ent_id = str(resolved["entity_id"])
                    doc_entity_ids.add(ent_id)
                    chunk_name_to_id[ent.name.lower()] = ent_id
                    chunk_name_to_id[str(resolved["canonical_name"]).lower()] = ent_id
                    for al in resolved.get("aliases", []):  # type: ignore[union-attr]
                        chunk_name_to_id[str(al).lower()] = ent_id

                    # Upsert entity record
                    conn.execute(
                        """
                        INSERT INTO entities (
                            entity_id, tenant_id, canonical_name, normalized_key,
                            entity_type, aliases_json, description, confidence, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(tenant_id, entity_id) DO UPDATE SET
                            aliases_json = excluded.aliases_json,
                            description = CASE
                                WHEN length(excluded.description) > length(entities.description)
                                THEN excluded.description
                                ELSE entities.description
                            END,
                            confidence = MAX(entities.confidence, excluded.confidence),
                            updated_at = excluded.updated_at
                        """,
                        (
                            ent_id,
                            tenant_id,
                            str(resolved["canonical_name"]),
                            str(resolved["normalized_key"]),
                            str(resolved["entity_type"]),
                            json.dumps(resolved.get("aliases", [])),
                            str(resolved.get("description", "")),
                            float(resolved.get("confidence", 0.85)),
                            now,
                            now,
                        ),
                    )

                    # Insert mention provenance
                    m_id = compute_mention_id(tenant_id, ent_id, ext.chunk_id, ent.char_start)
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO entity_mentions (
                            mention_id, tenant_id, entity_id, doc_id, chunk_id,
                            surface_form, evidence_quote, char_start, char_end, confidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            m_id,
                            tenant_id,
                            ent_id,
                            doc_id,
                            ext.chunk_id,
                            ent.name,
                            ent.evidence_quote,
                            ent.char_start,
                            ent.char_end,
                            ent.confidence,
                        ),
                    )

                    # Persist any uncertain entity resolution candidates (without overwriting resolved audit records)
                    for unc in uncertain_list:
                        cur = conn.execute(
                            """
                            INSERT INTO uncertain_matches (
                                match_id, tenant_id, entity_a_id, entity_a_name,
                                entity_b_id, entity_b_name, entity_type,
                                similarity_score, reason, doc_id, status, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                            ON CONFLICT(tenant_id, match_id) DO UPDATE SET
                                similarity_score = excluded.similarity_score,
                                reason = excluded.reason,
                                doc_id = excluded.doc_id,
                                created_at = excluded.created_at
                            WHERE uncertain_matches.status = 'pending'
                            """,
                            (
                                unc["match_id"],
                                tenant_id,
                                unc["entity_a_id"],
                                unc["entity_a_name"],
                                unc["entity_b_id"],
                                unc["entity_b_name"],
                                unc["entity_type"],
                                unc["similarity_score"],
                                unc["reason"],
                                doc_id,
                                now,
                            ),
                        )
                        if cur.rowcount > 0:
                            uncertain_count_for_doc += 1

                # 3. Persist relationships
                for rel in ext.relationships:
                    src_id = chunk_name_to_id.get(rel.source_entity.lower())
                    tgt_id = chunk_name_to_id.get(rel.target_entity.lower())
                    if not src_id or not tgt_id or src_id == tgt_id:
                        continue

                    e_id = compute_edge_id(
                        tenant_id, src_id, tgt_id, rel.relationship_type.value, ext.chunk_id
                    )
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO relationships (
                            edge_id, tenant_id, source_id, target_id, relationship_type,
                            is_inferred, confidence, doc_id, chunk_id, evidence_quote,
                            char_start, char_end, temporal_marker, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            e_id,
                            tenant_id,
                            src_id,
                            tgt_id,
                            rel.relationship_type.value,
                            1 if rel.is_inferred else 0,
                            rel.confidence,
                            doc_id,
                            ext.chunk_id,
                            rel.evidence_quote,
                            rel.char_start,
                            rel.char_end,
                            rel.temporal_marker,
                            now,
                        ),
                    )
                    relationship_count_for_doc += 1

            entity_Count_for_doc = len(doc_entity_ids)

            # Clean up orphaned entities and pending matches whose entities no longer exist
            self._prune_orphaned_entities_and_matches(conn, tenant_id)

        # Invalidate cache and recompute communities after graph update
        self._invalidate_graph_cache(tenant_id)
        communities = self.recompute_communities(tenant_id)
        return {
            "chunk_count": len(chunks),
            "entity_count": entity_Count_for_doc,
            "relationship_count": relationship_count_for_doc,
            "uncertain_match_count": uncertain_count_for_doc,
            "community_count": len(communities),
        }

    def delete_document_and_artifacts(self, tenant_id: str, doc_id: str) -> bool:
        """
        Atomically delete a document, its chunks, mentions, relationships, and any
        entities that become orphaned, then recompute graph communities.
        """
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT doc_id FROM documents WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            ).fetchone()
            if not row:
                return False

            conn.execute(
                "DELETE FROM relationships WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            )
            conn.execute(
                "DELETE FROM entity_mentions WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            )
            conn.execute(
                "DELETE FROM uncertain_matches WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            )
            conn.execute(
                "DELETE FROM chunks WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            )
            conn.execute(
                "DELETE FROM documents WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            )
            # Prune orphaned entities and pending uncertain matches referencing deleted entities
            self._prune_orphaned_entities_and_matches(conn, tenant_id)

        self._invalidate_graph_cache(tenant_id)
        self.recompute_communities(tenant_id)
        return True

    def build_networkx_graph(
        self, tenant_id: str, doc_ids: Optional[List[str]] = None
    ) -> nx.MultiDiGraph:
        """Construct an in-memory NetworkX MultiDiGraph scoped to the caller's tenant and authorized doc_ids (with versioned caching)."""
        if doc_ids is not None and len(doc_ids) == 0:
            return nx.MultiDiGraph()

        db_key = self._resolved_db_key()
        scope_key: Optional[Tuple[str, ...]] = tuple(sorted(set(doc_ids))) if doc_ids is not None else None
        cache_key = (db_key, tenant_id, scope_key)
        write_ver = self._WRITE_VERSIONS.get((db_key, tenant_id), 0)
        cached = self._GRAPH_CACHE.get(cache_key)
        if cached is not None and cached[0] == write_ver:
            return cached[1].copy()

        G = nx.MultiDiGraph()

        with get_db_connection(self.db_path) as conn:
            ent_rows = conn.execute(
                """
                SELECT entity_id, canonical_name, entity_type, aliases_json,
                       description, confidence, community_id
                FROM entities
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            ).fetchall()

            doc_filter_sql = ""
            rel_params: List[object] = [tenant_id]
            if doc_ids is not None:
                placeholders = ",".join("?" for _ in doc_ids)
                doc_filter_sql = f" AND r.doc_id IN ({placeholders})"
                rel_params.extend(doc_ids)

            rel_rows = conn.execute(
                f"""
                SELECT r.edge_id, r.source_id, r.target_id, r.relationship_type,
                       r.is_inferred, r.confidence, r.doc_id, r.chunk_id,
                       r.evidence_quote, r.char_start, r.char_end, r.temporal_marker,
                       d.filename
                FROM relationships r
                JOIN documents d ON d.tenant_id = r.tenant_id AND d.doc_id = r.doc_id
                WHERE r.tenant_id = ?{doc_filter_sql}
                """,
                rel_params,
            ).fetchall()

            mention_rows = conn.execute(
                """
                SELECT entity_id, doc_id, chunk_id, surface_form, evidence_quote
                FROM entity_mentions
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            ).fetchall()

        allowed_doc_set = set(doc_ids) if doc_ids is not None else None
        doc_map_by_ent: Dict[str, Set[str]] = {}
        mentions_by_ent: Dict[str, List[Dict[str, Any]]] = {}
        for m in mention_rows:
            if allowed_doc_set is not None and m["doc_id"] not in allowed_doc_set:
                continue
            eid = m["entity_id"]
            doc_map_by_ent.setdefault(eid, set()).add(m["doc_id"])
            mentions_by_ent.setdefault(eid, []).append(
                {
                    "doc_id": m["doc_id"],
                    "chunk_id": m["chunk_id"],
                    "surface_form": m["surface_form"],
                    "evidence_quote": m["evidence_quote"],
                }
            )

        for r in ent_rows:
            eid = r["entity_id"]
            if allowed_doc_set is not None and eid not in doc_map_by_ent:
                continue
            G.add_node(
                eid,
                entity_id=eid,
                canonical_name=r["canonical_name"],
                entity_type=r["entity_type"],
                aliases=json.loads(r["aliases_json"] or "[]"),
                description=r["description"],
                confidence=float(r["confidence"]),
                community_id=r["community_id"],
                document_ids=sorted(doc_map_by_ent.get(eid, set())),
                mentions=mentions_by_ent.get(eid, [])[:10],
            )

        for rel in rel_rows:
            u = rel["source_id"]
            v = rel["target_id"]
            if u in G and v in G:
                G.add_edge(
                    u,
                    v,
                    key=rel["edge_id"],
                    edge_id=rel["edge_id"],
                    relationship_type=rel["relationship_type"],
                    is_inferred=bool(rel["is_inferred"]),
                    confidence=float(rel["confidence"]),
                    doc_id=rel["doc_id"],
                    filename=rel["filename"],
                    chunk_id=rel["chunk_id"],
                    evidence_quote=rel["evidence_quote"],
                    char_start=int(rel["char_start"]),
                    char_end=int(rel["char_end"]),
                    temporal_marker=rel["temporal_marker"],
                )

        if len(self._GRAPH_CACHE) >= self._MAX_CACHE_ENTRIES:
            oldest_key = next(iter(self._GRAPH_CACHE))
            self._GRAPH_CACHE.pop(oldest_key, None)
        self._GRAPH_CACHE[cache_key] = (write_ver, G.copy())

        return G

    def recompute_communities(self, tenant_id: str) -> List[CommunityView]:
        """
        Detect thematic communities using NetworkX greedy modularity on the tenant's graph,
        synthesize evidence-backed summaries, and persist them in SQLite.
        """
        G = self.build_networkx_graph(tenant_id)
        now = utc_now_iso()
        communities_out: List[CommunityView] = []

        with get_db_connection(self.db_path) as conn:
            conn.execute("DELETE FROM communities WHERE tenant_id = ?", (tenant_id,))
            conn.execute("UPDATE entities SET community_id = NULL WHERE tenant_id = ?", (tenant_id,))

            if G.number_of_nodes() == 0:
                return []

            undirected = nx.Graph()
            for n, data in G.nodes(data=True):
                undirected.add_node(n, **data)
            for u, v, _data in G.edges(data=True):
                if u != v:
                    undirected.add_edge(u, v)

            if undirected.number_of_edges() > 0:
                try:
                    raw_comms = list(nx.community.greedy_modularity_communities(undirected))
                except Exception:
                    raw_comms = list(nx.connected_components(undirected))
            else:
                raw_comms = [set(undirected.nodes())]

            # Sort largest communities first
            raw_comms.sort(key=lambda c: len(c), reverse=True)

            for idx, comm_nodes in enumerate(raw_comms, start=1):
                if not comm_nodes:
                    continue
                comm_id = f"comm-{tenant_id[:8]}-{idx:02d}"
                sub = G.subgraph(comm_nodes)
                # Rank entities by degree centrality inside community
                deg_map = dict(sub.degree())
                sorted_nodes = sorted(comm_nodes, key=lambda nid: deg_map.get(nid, 0), reverse=True)

                entity_names = [str(G.nodes[nid]["canonical_name"]) for nid in sorted_nodes]
                type_counts = Counter(str(G.nodes[nid]["entity_type"]) for nid in sorted_nodes)
                dominant_types = [t for t, _ in type_counts.most_common(3)]

                source_docs: Set[str] = set()
                for nid in sorted_nodes:
                    source_docs.update(G.nodes[nid].get("document_ids", []))

                edge_summaries: List[str] = []
                for u, v, edata in sub.edges(data=True):
                    u_name = G.nodes[u]["canonical_name"]
                    v_name = G.nodes[v]["canonical_name"]
                    rtype = edata["relationship_type"]
                    tmark = f" ({edata['temporal_marker']})" if edata.get("temporal_marker") else ""
                    edge_summaries.append(f"{u_name} -[{rtype}]-> {v_name}{tmark}")

                lead_names = ", ".join(entity_names[:3])
                title = f"Cluster {idx}: {lead_names}"
                rel_preview = "; ".join(edge_summaries[:6]) if edge_summaries else "Co-occurring domain entities"
                summary = (
                    f"Community '{title}' encompasses {len(comm_nodes)} entities "
                    f"(predominantly {', '.join(dominant_types)}) and {sub.number_of_edges()} relationships "
                    f"across {len(source_docs)} document(s). Key relationships: {rel_preview}."
                )

                conn.execute(
                    """
                    INSERT INTO communities (
                        community_id, tenant_id, level, title, summary,
                        entity_ids_json, entity_names_json, relationship_count,
                        dominant_types_json, source_doc_ids_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        comm_id,
                        tenant_id,
                        0,
                        title,
                        summary,
                        json.dumps(sorted_nodes),
                        json.dumps(entity_names),
                        sub.number_of_edges(),
                        json.dumps(dominant_types),
                        json.dumps(sorted(source_docs)),
                        now,
                    ),
                )

                for nid in sorted_nodes:
                    conn.execute(
                        "UPDATE entities SET community_id = ? WHERE tenant_id = ? AND entity_id = ?",
                        (comm_id, tenant_id, nid),
                    )

                communities_out.append(
                    CommunityView(
                        community_id=comm_id,
                        tenant_id=tenant_id,
                        level=0,
                        title=title,
                        summary=summary,
                        entity_count=len(sorted_nodes),
                        entity_names=entity_names,
                        relationship_count=sub.number_of_edges(),
                        dominant_types=dominant_types,
                        source_doc_ids=sorted(source_docs),
                        updated_at=now,
                    )
                )

        return communities_out

    def get_communities(
        self,
        tenant_id: str,
        authorized_doc_ids: Optional[List[str]] = None,
        doc_ids: Optional[List[str]] = None,
    ) -> List[CommunityView]:
        """Retrieve persisted communities for a tenant, filtered by authorized_doc_ids when provided."""
        eff_docs = authorized_doc_ids if authorized_doc_ids is not None else doc_ids
        if eff_docs is not None and len(eff_docs) == 0:
            return []
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT community_id, tenant_id, level, title, summary,
                       entity_names_json, relationship_count, dominant_types_json,
                       source_doc_ids_json, updated_at
                FROM communities
                WHERE tenant_id = ?
                ORDER BY relationship_count DESC, community_id ASC
                """,
                (tenant_id,),
            ).fetchall()

        allowed_set = set(eff_docs) if eff_docs is not None else None
        results: List[CommunityView] = []
        for r in rows:
            src_docs = json.loads(r["source_doc_ids_json"] or "[]")
            if allowed_set is not None:
                # Only expose communities whose source documents are all within the user's authorized scope
                if not src_docs or not all(d in allowed_set for d in src_docs):
                    continue
            names = json.loads(r["entity_names_json"] or "[]")
            results.append(
                CommunityView(
                    community_id=r["community_id"],
                    tenant_id=r["tenant_id"],
                    level=int(r["level"]),
                    title=r["title"],
                    summary=r["summary"],
                    entity_count=len(names),
                    entity_names=names,
                    relationship_count=int(r["relationship_count"]),
                    dominant_types=json.loads(r["dominant_types_json"] or "[]"),
                    source_doc_ids=src_docs,
                    updated_at=r["updated_at"],
                )
            )
        return results

    def explore_subgraph(
        self,
        tenant_id: str,
        search_query: Optional[str] = None,
        entity_type: Optional[str] = None,
        relationship_type: Optional[str] = None,
        doc_id: Optional[str] = None,
        authorized_doc_ids: Optional[List[str]] = None,
        doc_ids: Optional[List[str]] = None,
        include_inferred: bool = True,
        limit_nodes: int = 80,
    ) -> Dict[str, Any]:
        """
        Return a bounded, readable subgraph for the Knowledge Graph Explorer UI with filters,
        strictly scoped to `authorized_doc_ids`.
        """
        base_docs = authorized_doc_ids if authorized_doc_ids is not None else doc_ids
        effective_doc_ids: Optional[List[str]] = base_docs
        if doc_id:
            if base_docs is not None:
                effective_doc_ids = [d for d in base_docs if d == doc_id]
            else:
                effective_doc_ids = [doc_id]

        G = self.build_networkx_graph(tenant_id, doc_ids=effective_doc_ids)

        matched_nodes: List[str] = []
        q_lower = search_query.strip().lower() if search_query else ""

        for nid, data in G.nodes(data=True):
            if entity_type and data.get("entity_type") != entity_type:
                continue
            if q_lower:
                name_match = q_lower in str(data.get("canonical_name", "")).lower()
                alias_match = any(q_lower in str(a).lower() for a in data.get("aliases", []))
                desc_match = q_lower in str(data.get("description", "")).lower()
                if not (name_match or alias_match or desc_match):
                    continue
            matched_nodes.append(nid)

        # Include 1-hop neighbors of matched nodes if search_query is active
        selected_set: Set[str] = set(matched_nodes)
        if q_lower and matched_nodes:
            for nid in list(matched_nodes):
                for nbr in nx.all_neighbors(G, nid):
                    if len(selected_set) < limit_nodes:
                        selected_set.add(nbr)

        # Sort by degree so highest-connectivity nodes are shown first within limit_nodes
        deg_map = dict(G.degree())
        ordered_nodes = sorted(selected_set, key=lambda n: deg_map.get(n, 0), reverse=True)[:limit_nodes]
        keep_set = set(ordered_nodes)

        nodes_out: List[GraphNodeView] = []
        for nid in ordered_nodes:
            d = G.nodes[nid]
            nodes_out.append(
                GraphNodeView(
                    entity_id=nid,
                    canonical_name=d["canonical_name"],
                    entity_type=EntityType(d["entity_type"]),
                    aliases=d.get("aliases", []),
                    description=d.get("description", ""),
                    confidence=d.get("confidence", 0.85),
                    degree=deg_map.get(nid, 0),
                    community_id=d.get("community_id"),
                    document_ids=d.get("document_ids", []),
                    mentions=d.get("mentions", []),
                )
            )

        edges_out: List[GraphEdgeView] = []
        for u, v, edata in G.edges(data=True):
            if u not in keep_set or v not in keep_set:
                continue
            if not include_inferred and edata.get("is_inferred"):
                continue
            if relationship_type and edata.get("relationship_type") != relationship_type:
                continue
            edges_out.append(
                GraphEdgeView(
                    edge_id=edata["edge_id"],
                    source_id=u,
                    source_name=G.nodes[u]["canonical_name"],
                    target_id=v,
                    target_name=G.nodes[v]["canonical_name"],
                    relationship_type=RelationshipType(edata["relationship_type"]),
                    is_inferred=bool(edata["is_inferred"]),
                    confidence=float(edata["confidence"]),
                    doc_id=edata["doc_id"],
                    filename=edata.get("filename", ""),
                    chunk_id=edata["chunk_id"],
                    evidence_quote=edata["evidence_quote"],
                    char_start=edata.get("char_start", 0),
                    char_end=edata.get("char_end", 0),
                    temporal_marker=edata.get("temporal_marker"),
                )
            )

        return {
            "total_graph_nodes": G.number_of_nodes(),
            "total_graph_edges": G.number_of_edges(),
            "returned_nodes": len(nodes_out),
            "returned_edges": len(edges_out),
            "nodes": [n.model_dump() for n in nodes_out],
            "edges": [e.model_dump() for e in edges_out],
        }

    def retrieve_entity_paths_and_context(
        self,
        tenant_id: str,
        query: str,
        max_hops: int = 2,
        include_inferred: bool = True,
        doc_ids: Optional[List[str]] = None,
    ) -> Tuple[List[GraphPathCitation], Set[str]]:
        """
        Find entities matching query terms, traverse up to max_hops, discover shortest paths
        between co-queried entities, and return traceable GraphPathCitations and supporting chunk_ids.
        """
        G = self.build_networkx_graph(tenant_id, doc_ids=doc_ids)
        if G.number_of_nodes() == 0:
            return [], set()

        q_lower = query.lower()
        q_tokens = {t for t in q_lower.replace("?", " ").replace(",", " ").split() if len(t) >= 3}

        seed_nodes: List[Tuple[str, float]] = []
        for nid, data in G.nodes(data=True):
            cname = str(data.get("canonical_name", ""))
            cname_lower = cname.lower()
            aliases = [str(a).lower() for a in data.get("aliases", [])]

            score = 0.0
            if cname_lower in q_lower:
                score = 1.0
            elif any(a in q_lower for a in aliases if len(a) >= 2):
                score = 0.95
            else:
                node_tokens = {t for t in cname_lower.split() if len(t) >= 3}
                overlap = len(q_tokens & node_tokens)
                if overlap > 0:
                    score = 0.45 * overlap

            if score > 0:
                seed_nodes.append((nid, score))

        seed_nodes.sort(key=lambda x: x[1], reverse=True)
        top_seeds = [nid for nid, _ in seed_nodes[:6]]
        if not top_seeds:
            return [], set()

        # Build an undirected view for multi-hop path discovery (while preserving directed edge provenance)
        U = nx.Graph()
        for u, v, edata in G.edges(data=True):
            if not include_inferred and edata.get("is_inferred"):
                continue
            U.add_edge(u, v)

        paths_out: List[GraphPathCitation] = []
        supporting_chunk_ids: Set[str] = set()
        seen_path_signatures: Set[str] = set()

        def format_node_chain(node_chain: List[str]) -> Optional[GraphPathCitation]:
            if len(node_chain) < 2:
                return None
            edge_objs: List[Dict[str, Any]] = []
            text_segments: List[str] = [str(G.nodes[node_chain[0]]["canonical_name"])]
            has_inferred = False
            min_conf = 1.0
            doc_set: Set[str] = set()

            for i in range(len(node_chain) - 1):
                a, b = node_chain[i], node_chain[i + 1]
                # Check forward edges a -> b then reverse b -> a
                chosen_edge: Optional[Dict[str, Any]] = None
                direction = "->"
                if G.has_edge(a, b):
                    for _, ed in G[a][b].items():
                        if not include_inferred and ed.get("is_inferred"):
                            continue
                        chosen_edge = ed
                        direction = "->"
                        break
                if chosen_edge is None and G.has_edge(b, a):
                    for _, ed in G[b][a].items():
                        if not include_inferred and ed.get("is_inferred"):
                            continue
                        chosen_edge = ed
                        direction = "<-"
                        break
                if chosen_edge is None:
                    return None

                if chosen_edge.get("is_inferred"):
                    has_inferred = True
                min_conf = min(min_conf, float(chosen_edge.get("confidence", 0.8)))
                doc_set.add(str(chosen_edge["doc_id"]))
                supporting_chunk_ids.add(str(chosen_edge["chunk_id"]))

                rel_label = chosen_edge["relationship_type"]
                if chosen_edge.get("is_inferred"):
                    rel_label += " (inferred)"
                if chosen_edge.get("temporal_marker"):
                    rel_label += f" @{chosen_edge['temporal_marker']}"

                b_name = str(G.nodes[b]["canonical_name"])
                if direction == "->":
                    text_segments.append(f"-[{rel_label}]-> {b_name}")
                else:
                    text_segments.append(f"<-[{rel_label}]- {b_name}")

                edge_objs.append(
                    {
                        "edge_id": chosen_edge["edge_id"],
                        "source": G.nodes[a]["canonical_name"] if direction == "->" else b_name,
                        "target": b_name if direction == "->" else G.nodes[a]["canonical_name"],
                        "relationship_type": chosen_edge["relationship_type"],
                        "is_inferred": bool(chosen_edge["is_inferred"]),
                        "confidence": float(chosen_edge["confidence"]),
                        "doc_id": chosen_edge["doc_id"],
                        "filename": chosen_edge.get("filename", ""),
                        "chunk_id": chosen_edge["chunk_id"],
                        "evidence_quote": chosen_edge["evidence_quote"],
                        "temporal_marker": chosen_edge.get("temporal_marker"),
                    }
                )

            path_str = " ".join(text_segments)
            if path_str in seen_path_signatures:
                return None
            seen_path_signatures.add(path_str)

            pid_hash = hashlib.sha256(path_str.encode("utf-8")).hexdigest()[:10]
            return GraphPathCitation(
                path_id=f"pth-{pid_hash}",
                nodes=[str(G.nodes[n]["canonical_name"]) for n in node_chain],
                node_ids=list(node_chain),
                edge_ids=[str(eo["edge_id"]) for eo in edge_objs],
                edges=edge_objs,
                path_text=path_str,
                has_inferred_edge=has_inferred,
                min_confidence=round(min_conf, 3),
                source_doc_ids=sorted(doc_set),
            )

        # 1. Shortest paths between pairs of seed entities (up to max_hops + 1)
        for i in range(len(top_seeds)):
            for j in range(i + 1, len(top_seeds)):
                s_a, s_b = top_seeds[i], top_seeds[j]
                if s_a in U and s_b in U and nx.has_path(U, s_a, s_b):
                    try:
                        sp = nx.shortest_path(U, s_a, s_b)
                        if len(sp) - 1 <= max_hops + 1:
                            pc = format_node_chain(sp)
                            if pc:
                                paths_out.append(pc)
                    except nx.NetworkXNoPath:
                        pass

        # 2. Multi-hop ego traversal from each seed entity
        for seed in top_seeds:
            for m in G.nodes[seed].get("mentions", []):
                supporting_chunk_ids.add(str(m["chunk_id"]))
            if seed not in U:
                continue
            for nbr1 in U.neighbors(seed):
                pc1 = format_node_chain([seed, nbr1])
                if pc1:
                    paths_out.append(pc1)
                if max_hops >= 2:
                    for nbr2 in U.neighbors(nbr1):
                        if nbr2 != seed:
                            pc2 = format_node_chain([seed, nbr1, nbr2])
                            if pc2 and len(paths_out) < 18:
                                paths_out.append(pc2)

        # Prioritize multi-hop paths and explicit high-confidence paths
        paths_out.sort(
            key=lambda p: (len(p.nodes) > 2, not p.has_inferred_edge, p.min_confidence),
            reverse=True,
        )
        return paths_out[:12], supporting_chunk_ids

    def list_authorized_entities(
        self,
        tenant_id: str,
        doc_ids: Optional[List[str]] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Return lightweight entity summaries scoped to authorized doc_ids for explorer dropdowns."""
        G = self.build_networkx_graph(tenant_id, doc_ids=doc_ids)
        deg_map = dict(G.degree())
        items = [
            {
                "entity_id": nid,
                "canonical_name": str(d.get("canonical_name", nid)),
                "entity_type": str(d.get("entity_type", "CONCEPT")),
                "degree": int(deg_map.get(nid, 0)),
            }
            for nid, d in G.nodes(data=True)
        ]
        items.sort(key=lambda x: (-x["degree"], x["canonical_name"].lower()))
        return items[:limit]

    def find_shortest_paths(
        self,
        tenant_id: str,
        source_entity_id: str,
        target_entity_id: str,
        max_hops: int = 4,
        include_inferred: bool = True,
        max_paths: int = 3,
        doc_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Compute shortest paths between two authorized entities within `max_hops`.
        Builds the ACL-filtered graph BEFORE traversal to guarantee zero hidden-entity leakage,
        and returns full `path_nodes` / `path_edges` for canvas union-merging.
        """
        G = self.build_networkx_graph(tenant_id, doc_ids=doc_ids)
        if source_entity_id not in G or target_entity_id not in G:
            return {
                "found": False,
                "hop_count": 0,
                "paths": [],
                "path_nodes": [],
                "path_edges": [],
                "message": "One or both entities were not found within your authorized document scope.",
            }

        deg_map = dict(G.degree())

        def build_node_view(nid: str) -> GraphNodeView:
            d = G.nodes[nid]
            return GraphNodeView(
                entity_id=nid,
                canonical_name=str(d["canonical_name"]),
                entity_type=EntityType(d["entity_type"]),
                aliases=d.get("aliases", []),
                description=str(d.get("description", "")),
                confidence=float(d.get("confidence", 0.85)),
                degree=int(deg_map.get(nid, 0)),
                community_id=d.get("community_id"),
                document_ids=d.get("document_ids", []),
                mentions=d.get("mentions", []),
            )

        if source_entity_id == target_entity_id:
            nv = build_node_view(source_entity_id)
            return {
                "found": True,
                "hop_count": 0,
                "paths": [],
                "path_nodes": [nv.model_dump()],
                "path_edges": [],
                "message": f"Source and target are the same entity ({nv.canonical_name}).",
            }

        U = nx.Graph()
        for n in G.nodes():
            U.add_node(n)
        for u, v, edata in G.edges(data=True):
            if not include_inferred and edata.get("is_inferred"):
                continue
            U.add_edge(u, v)

        if not nx.has_path(U, source_entity_id, target_entity_id):
            src_name = G.nodes[source_entity_id]["canonical_name"]
            tgt_name = G.nodes[target_entity_id]["canonical_name"]
            return {
                "found": False,
                "hop_count": 0,
                "paths": [],
                "path_nodes": [build_node_view(source_entity_id).model_dump(), build_node_view(target_entity_id).model_dump()],
                "path_edges": [],
                "message": f"No connected path found between '{src_name}' and '{tgt_name}' with current filters.",
            }

        raw_chains = list(itertools.islice(nx.all_shortest_paths(U, source_entity_id, target_entity_id), max_paths))
        shortest_hops = len(raw_chains[0]) - 1 if raw_chains else 0
        if shortest_hops > max_hops:
            return {
                "found": False,
                "hop_count": shortest_hops,
                "paths": [],
                "path_nodes": [build_node_view(source_entity_id).model_dump(), build_node_view(target_entity_id).model_dump()],
                "path_edges": [],
                "message": f"Shortest path requires {shortest_hops} hop(s), exceeding max_hops={max_hops}. Increase Max Hops to view it.",
            }

        def choose_best_edge(a: str, b: str) -> Tuple[Optional[Dict[str, Any]], str]:
            candidates: List[Tuple[bool, float, Dict[str, Any], str]] = []
            if G.has_edge(a, b):
                for _, ed in G[a][b].items():
                    if not include_inferred and ed.get("is_inferred"):
                        continue
                    candidates.append((not bool(ed.get("is_inferred")), float(ed.get("confidence", 0.8)), ed, "->"))
            if G.has_edge(b, a):
                for _, ed in G[b][a].items():
                    if not include_inferred and ed.get("is_inferred"):
                        continue
                    candidates.append((not bool(ed.get("is_inferred")), float(ed.get("confidence", 0.8)), ed, "<-"))
            if not candidates:
                return None, "->"
            candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
            _, _, best_ed, best_dir = candidates[0]
            return best_ed, best_dir

        paths_out: List[GraphPathCitation] = []
        collected_node_ids: Set[str] = set()
        collected_edges: Dict[str, GraphEdgeView] = {}

        for chain in raw_chains:
            edge_objs: List[Dict[str, Any]] = []
            edge_ids: List[str] = []
            text_segments: List[str] = [str(G.nodes[chain[0]]["canonical_name"])]
            has_inferred = False
            min_conf = 1.0
            doc_set: Set[str] = set()
            valid_chain = True

            for nid in chain:
                collected_node_ids.add(nid)

            for i in range(len(chain) - 1):
                a, b = chain[i], chain[i + 1]
                chosen_edge, direction = choose_best_edge(a, b)
                if chosen_edge is None:
                    valid_chain = False
                    break

                src_id = a if direction == "->" else b
                tgt_id = b if direction == "->" else a
                eid = str(chosen_edge["edge_id"])
                edge_ids.append(eid)
                if chosen_edge.get("is_inferred"):
                    has_inferred = True
                min_conf = min(min_conf, float(chosen_edge.get("confidence", 0.8)))
                doc_set.add(str(chosen_edge["doc_id"]))

                rel_label = str(chosen_edge["relationship_type"])
                if chosen_edge.get("is_inferred"):
                    rel_label += " (inferred)"
                if chosen_edge.get("temporal_marker"):
                    rel_label += f" @{chosen_edge['temporal_marker']}"

                b_name = str(G.nodes[b]["canonical_name"])
                if direction == "->":
                    text_segments.append(f"-[{rel_label}]-> {b_name}")
                else:
                    text_segments.append(f"<-[{rel_label}]- {b_name}")

                edge_objs.append(
                    {
                        "edge_id": eid,
                        "source_id": src_id,
                        "target_id": tgt_id,
                        "source": str(G.nodes[src_id]["canonical_name"]),
                        "target": str(G.nodes[tgt_id]["canonical_name"]),
                        "relationship_type": chosen_edge["relationship_type"],
                        "is_inferred": bool(chosen_edge["is_inferred"]),
                        "confidence": float(chosen_edge["confidence"]),
                        "doc_id": chosen_edge["doc_id"],
                        "filename": chosen_edge.get("filename", ""),
                        "chunk_id": chosen_edge["chunk_id"],
                        "evidence_quote": chosen_edge["evidence_quote"],
                        "temporal_marker": chosen_edge.get("temporal_marker"),
                    }
                )
                if eid not in collected_edges:
                    collected_edges[eid] = GraphEdgeView(
                        edge_id=eid,
                        source_id=src_id,
                        source_name=str(G.nodes[src_id]["canonical_name"]),
                        target_id=tgt_id,
                        target_name=str(G.nodes[tgt_id]["canonical_name"]),
                        relationship_type=RelationshipType(chosen_edge["relationship_type"]),
                        is_inferred=bool(chosen_edge["is_inferred"]),
                        confidence=float(chosen_edge["confidence"]),
                        doc_id=str(chosen_edge["doc_id"]),
                        filename=str(chosen_edge.get("filename", "")),
                        chunk_id=str(chosen_edge["chunk_id"]),
                        evidence_quote=str(chosen_edge["evidence_quote"]),
                        char_start=int(chosen_edge.get("char_start", 0)),
                        char_end=int(chosen_edge.get("char_end", 0)),
                        temporal_marker=chosen_edge.get("temporal_marker"),
                    )

            if not valid_chain:
                continue

            path_str = " ".join(text_segments)
            pid_hash = hashlib.sha256(path_str.encode("utf-8")).hexdigest()[:10]
            paths_out.append(
                GraphPathCitation(
                    path_id=f"pth-{pid_hash}",
                    nodes=[str(G.nodes[n]["canonical_name"]) for n in chain],
                    node_ids=list(chain),
                    edge_ids=edge_ids,
                    edges=edge_objs,
                    path_text=path_str,
                    has_inferred_edge=has_inferred,
                    min_confidence=round(min_conf, 3),
                    source_doc_ids=sorted(doc_set),
                )
            )

        path_nodes = [build_node_view(nid).model_dump() for nid in collected_node_ids]
        path_edges = [ev.model_dump() for ev in collected_edges.values()]
        return {
            "found": len(paths_out) > 0,
            "hop_count": shortest_hops,
            "paths": [p.model_dump() for p in paths_out],
            "path_nodes": path_nodes,
            "path_edges": path_edges,
            "message": f"Found {len(paths_out)} shortest path(s) spanning {shortest_hops} hop(s).",
        }

    def resolve_uncertain_match(
        self,
        tenant_id: str,
        match_id: str,
        action: str,
        actor_user_id: str,
        canonical_entity_id: Optional[str] = None,
        note: str = "",
        authorized_doc_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Atomically resolve a flagged uncertain entity match via either `merge` or `keep_distinct`.
        Persists permanent entity resolution decisions and enforces document-level ACL scope.
        """
        now = utc_now_iso()
        auth_set = set(authorized_doc_ids) if authorized_doc_ids is not None else None

        with get_db_connection(self.db_path) as conn:
            match_row = conn.execute(
                """
                SELECT match_id, tenant_id, entity_a_id, entity_a_name,
                       entity_b_id, entity_b_name, entity_type,
                       similarity_score, reason, doc_id, status
                FROM uncertain_matches
                WHERE tenant_id = ? AND match_id = ?
                """,
                (tenant_id, match_id),
            ).fetchone()

            if not match_row:
                raise LookupError(f"Uncertain match '{match_id}' was not found.")
            if str(match_row["status"] or "pending") != "pending":
                raise RuntimeError(f"Uncertain match '{match_id}' has already been resolved ({match_row['status']}).")

            ent_a_id = str(match_row["entity_a_id"])
            ent_b_id = str(match_row["entity_b_id"])
            ent_type_str = str(match_row["entity_type"])

            # Verify caller's ACL covers the flagged document AND all mentions of both candidate entities
            if auth_set is not None:
                if str(match_row["doc_id"]) not in auth_set:
                    raise PermissionError("You are not authorized to resolve matches from this document.")
                mention_doc_rows = conn.execute(
                    """
                    SELECT DISTINCT doc_id FROM entity_mentions
                    WHERE tenant_id = ? AND entity_id IN (?, ?)
                    """,
                    (tenant_id, ent_a_id, ent_b_id),
                ).fetchall()
                for mr in mention_doc_rows:
                    if str(mr["doc_id"]) not in auth_set:
                        raise PermissionError(
                            "One or more candidate entities appear in documents outside your authorized ACL scope."
                        )

            ent_a_row = conn.execute(
                "SELECT * FROM entities WHERE tenant_id = ? AND entity_id = ?",
                (tenant_id, ent_a_id),
            ).fetchone()
            ent_b_row = conn.execute(
                "SELECT * FROM entities WHERE tenant_id = ? AND entity_id = ?",
                (tenant_id, ent_b_id),
            ).fetchone()

            try:
                ent_type_enum = EntityType(ent_type_str)
            except Exception:
                ent_type_enum = EntityType.CONCEPT

            key_a = str(ent_a_row["normalized_key"]) if ent_a_row else normalize_entity_key(str(match_row["entity_a_name"]), ent_type_enum)
            key_b = str(ent_b_row["normalized_key"]) if ent_b_row else normalize_entity_key(str(match_row["entity_b_name"]), ent_type_enum)
            pair_sig = compute_pair_signature(tenant_id, ent_type_str, key_a, key_b)

            if action == "keep_distinct":
                conn.execute(
                    """
                    INSERT INTO entity_resolution_decisions (
                        tenant_id, pair_signature, entity_type, key_a, key_b,
                        decision, canonical_key, decided_by, decided_at
                    ) VALUES (?, ?, ?, ?, ?, 'kept_distinct', NULL, ?, ?)
                    ON CONFLICT(tenant_id, pair_signature) DO UPDATE SET
                        decision = 'kept_distinct',
                        canonical_key = NULL,
                        decided_by = excluded.decided_by,
                        decided_at = excluded.decided_at
                    """,
                    (tenant_id, pair_sig, ent_type_str, key_a, key_b, actor_user_id, now),
                )
                conn.execute(
                    """
                    UPDATE uncertain_matches
                    SET status = 'kept_distinct', resolved_by = ?, resolved_at = ?, resolution_note = ?
                    WHERE tenant_id = ? AND match_id = ?
                    """,
                    (actor_user_id, now, note.strip(), tenant_id, match_id),
                )
                return {
                    "match_id": match_id,
                    "status": "kept_distinct",
                    "action": "keep_distinct",
                    "entity_a_id": ent_a_id,
                    "entity_b_id": ent_b_id,
                    "resolved_by": actor_user_id,
                    "resolved_at": now,
                }

            # Action == "merge"
            if not ent_a_row or not ent_b_row:
                raise ValueError("Cannot merge because one of the candidate entities no longer exists.")

            keep_id = canonical_entity_id or ent_a_id
            if keep_id not in (ent_a_id, ent_b_id):
                raise ValueError(
                    f"canonical_entity_id must be either '{ent_a_id}' or '{ent_b_id}'."
                )
            drop_id = ent_b_id if keep_id == ent_a_id else ent_a_id
            keep_row = ent_a_row if keep_id == ent_a_id else ent_b_row
            drop_row = ent_b_row if drop_id == ent_b_id else ent_a_row

            # 1. Merge aliases, description, and confidence onto surviving entity
            keep_aliases = set(json.loads(keep_row["aliases_json"] or "[]"))
            drop_aliases = set(json.loads(drop_row["aliases_json"] or "[]"))
            merged_aliases = sorted(
                (keep_aliases | drop_aliases | {str(drop_row["canonical_name"])})
                - {str(keep_row["canonical_name"])}
            )
            merged_desc = (
                str(drop_row["description"])
                if len(str(drop_row["description"] or "")) > len(str(keep_row["description"] or ""))
                else str(keep_row["description"] or "")
            )
            merged_conf = max(float(keep_row["confidence"]), float(drop_row["confidence"]))

            conn.execute(
                """
                UPDATE entities
                SET aliases_json = ?, description = ?, confidence = ?, updated_at = ?
                WHERE tenant_id = ? AND entity_id = ?
                """,
                (json.dumps(merged_aliases), merged_desc, merged_conf, now, tenant_id, keep_id),
            )

            # 2. Remap mentions cleanly (avoid deterministic mention_id collisions)
            drop_mentions = conn.execute(
                """
                SELECT mention_id, doc_id, chunk_id, surface_form, evidence_quote,
                       char_start, char_end, confidence
                FROM entity_mentions
                WHERE tenant_id = ? AND entity_id = ?
                """,
                (tenant_id, drop_id),
            ).fetchall()
            for dm in drop_mentions:
                new_mid = compute_mention_id(tenant_id, keep_id, str(dm["chunk_id"]), int(dm["char_start"]))
                conn.execute(
                    """
                    INSERT OR IGNORE INTO entity_mentions (
                        mention_id, tenant_id, entity_id, doc_id, chunk_id,
                        surface_form, evidence_quote, char_start, char_end, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_mid,
                        tenant_id,
                        keep_id,
                        dm["doc_id"],
                        dm["chunk_id"],
                        dm["surface_form"],
                        dm["evidence_quote"],
                        dm["char_start"],
                        dm["char_end"],
                        dm["confidence"],
                    ),
                )
            conn.execute(
                "DELETE FROM entity_mentions WHERE tenant_id = ? AND entity_id = ?",
                (tenant_id, drop_id),
            )

            # 3. Remap relationships cleanly (drop self-loops & deduplicate deterministic edge_ids)
            drop_edges = conn.execute(
                """
                SELECT edge_id, source_id, target_id, relationship_type, is_inferred,
                       confidence, doc_id, chunk_id, evidence_quote,
                       char_start, char_end, temporal_marker, created_at
                FROM relationships
                WHERE tenant_id = ? AND (source_id = ? OR target_id = ?)
                """,
                (tenant_id, drop_id, drop_id),
            ).fetchall()
            for de in drop_edges:
                new_src = keep_id if de["source_id"] == drop_id else de["source_id"]
                new_tgt = keep_id if de["target_id"] == drop_id else de["target_id"]
                if new_src == new_tgt:
                    continue
                new_eid = compute_edge_id(
                    tenant_id, str(new_src), str(new_tgt), str(de["relationship_type"]), str(de["chunk_id"])
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO relationships (
                        edge_id, tenant_id, source_id, target_id, relationship_type,
                        is_inferred, confidence, doc_id, chunk_id, evidence_quote,
                        char_start, char_end, temporal_marker, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_eid,
                        tenant_id,
                        new_src,
                        new_tgt,
                        de["relationship_type"],
                        de["is_inferred"],
                        de["confidence"],
                        de["doc_id"],
                        de["chunk_id"],
                        de["evidence_quote"],
                        de["char_start"],
                        de["char_end"],
                        de["temporal_marker"],
                        de["created_at"],
                    ),
                )
            conn.execute(
                "DELETE FROM relationships WHERE tenant_id = ? AND (source_id = ? OR target_id = ?)",
                (tenant_id, drop_id, drop_id),
            )

            # 4. Update other pending uncertain_matches referencing drop_id
            keep_name = str(keep_row["canonical_name"])
            conn.execute(
                """
                UPDATE uncertain_matches
                SET entity_a_id = ?, entity_a_name = ?
                WHERE tenant_id = ? AND match_id != ? AND status = 'pending' AND entity_a_id = ?
                """,
                (keep_id, keep_name, tenant_id, match_id, drop_id),
            )
            conn.execute(
                """
                UPDATE uncertain_matches
                SET entity_b_id = ?, entity_b_name = ?
                WHERE tenant_id = ? AND match_id != ? AND status = 'pending' AND entity_b_id = ?
                """,
                (keep_id, keep_name, tenant_id, match_id, drop_id),
            )
            conn.execute(
                """
                UPDATE uncertain_matches
                SET status = 'merged', resolved_by = ?, resolved_at = ?,
                    resolution_note = 'Auto-closed after entity merge'
                WHERE tenant_id = ? AND match_id != ? AND status = 'pending' AND entity_a_id = entity_b_id
                """,
                (actor_user_id, now, tenant_id, match_id),
            )

            # 5. Delete merged entity
            conn.execute(
                "DELETE FROM entities WHERE tenant_id = ? AND entity_id = ?",
                (tenant_id, drop_id),
            )

            # 6. Persist resolution decision and update target match row
            conn.execute(
                """
                INSERT INTO entity_resolution_decisions (
                    tenant_id, pair_signature, entity_type, key_a, key_b,
                    decision, canonical_key, decided_by, decided_at
                ) VALUES (?, ?, ?, ?, ?, 'merged', ?, ?, ?)
                ON CONFLICT(tenant_id, pair_signature) DO UPDATE SET
                    decision = 'merged',
                    canonical_key = excluded.canonical_key,
                    decided_by = excluded.decided_by,
                    decided_at = excluded.decided_at
                """,
                (tenant_id, pair_sig, ent_type_str, key_a, key_b, keep_row["normalized_key"], actor_user_id, now),
            )
            conn.execute(
                """
                UPDATE uncertain_matches
                SET status = 'merged', resolved_by = ?, resolved_at = ?, resolution_note = ?
                WHERE tenant_id = ? AND match_id = ?
                """,
                (actor_user_id, now, note.strip(), tenant_id, match_id),
            )

        self._invalidate_graph_cache(tenant_id)
        self.recompute_communities(tenant_id)
        return {
            "match_id": match_id,
            "status": "merged",
            "action": "merge",
            "canonical_entity_id": keep_id,
            "canonical_name": keep_name,
            "merged_entity_id": drop_id,
            "aliases": merged_aliases,
            "resolved_by": actor_user_id,
            "resolved_at": now,
        }
