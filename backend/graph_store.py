"""Knowledge graph construction, idempotency, community detection, and multi-hop traversal."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from backend.database import get_db_connection
from backend.entity_resolution import EntityResolver
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

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path

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
        resolver = EntityResolver(existing_entities=existing_entities, tenant_id=tenant_id)

        entity_Count_for_doc = 0
        relationship_count_for_doc = 0
        uncertain_count_for_doc = 0

        with get_db_connection(self.db_path) as conn:
            # Remove prior chunks/mentions/edges for this doc_id to ensure idempotent re-indexing
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

                    # Persist any uncertain entity resolution candidates
                    for unc in uncertain_list:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO uncertain_matches (
                                match_id, tenant_id, entity_a_id, entity_a_name,
                                entity_b_id, entity_b_name, entity_type,
                                similarity_score, reason, doc_id, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

            # Clean up any orphaned entities that no longer have mentions in any document
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

        # Recompute communities after graph update
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
            # Prune orphaned entities that have zero remaining mentions
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

        self.recompute_communities(tenant_id)
        return True

    def build_networkx_graph(
        self, tenant_id: str, doc_ids: Optional[List[str]] = None
    ) -> nx.MultiDiGraph:
        """Construct an in-memory NetworkX MultiDiGraph scoped to the caller's tenant and authorized doc_ids."""
        G = nx.MultiDiGraph()
        if doc_ids is not None and len(doc_ids) == 0:
            return G

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
            for u, v, data in G.edges(data=True):
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
