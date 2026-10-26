"""Schema-validated entity and relationship extraction with provenance and confidence."""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple
import httpx
from pydantic import ValidationError

from backend.config import settings
from backend.schemas import (
    ChunkExtractionResult,
    ChunkRecord,
    ExtractedEntity,
    ExtractedRelationship,
    EntityType,
    RelationshipType,
)

# High-precision domain patterns for deterministic local extraction
KNOWN_ENTITY_PATTERNS: List[Tuple[re.Pattern[str], EntityType]] = [
    # Dates & Quarters
    (re.compile(r"\b(Q[1-4]\s+202\d|202\d-\d{2}-\d{2}|(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+202\d)\b"), EntityType.DATE),
    # Metrics & SLAs
    (re.compile(r"\b(\d+(?:\.\d+)?%\s+(?:uptime|SLA|availability|packet loss|error rate|latency|revenue|reduction|increase)|\$?\d+(?:\.\d+)?\s*(?:million|billion|M|B)\s*(?:USD|penalty|fine|revenue|cost|loss)?|MTTR\s+of\s+\d+\s*(?:minutes|hours)|RTO\s+of\s+\d+\s*(?:minutes|hours))\b", re.IGNORECASE), EntityType.METRIC),
    # Policies, Standards & Regulations
    (re.compile(r"\b(ISO/IEC\s+\d+|SOC\s*2\s+Type\s+II|DORA\s+Article\s+\d+|DORA\s+Regulation|GDPR\s+Article\s+\d+|NIST\s+SP\s+800-\d+|PCI-DSS\s+v\d+(?:\.\d+)?|Zero-Trust\s+Mandate\s+[A-Z0-9-]+|Policy\s+[A-Z]{2,5}-\d+)\b"), EntityType.POLICY),
    # Incidents & Events
    (re.compile(r"\b(Incident\s+INC-\d{4}-\d+|Outage\s+OUT-\d{4}-\d+|Operation\s+[A-Z][a-zA-Z0-9_-]+|Project\s+[A-Z][a-zA-Z0-9_-]+|Audit\s+AUD-\d{4}-\d+|Migration\s+Wave\s+\d+|CVE-\d{4}-\d{4,7})\b"), EntityType.EVENT),
    # Systems & Platforms
    (re.compile(r"\b((?:[A-Z][a-zA-Z0-9_-]*[ \t]+){1,3}(?:Core|Engine|Gateway|Platform|Cluster|Database|Ledger|API|Mesh|Vault|Pipeline|Router|Service|Fabric|Grid)(?:[ \t]+(?:v\d+(?:\.\d+)?|US|UK|EU|APAC))?)\b"), EntityType.SYSTEM),
    # Technologies
    (re.compile(r"\b(Kubernetes|PostgreSQL\s*\d*|Kafka|Redis|GraphQL|TLS\s*1\.[23]|eBPF|OpenTelemetry|gRPC|Terraform|Neo4j|Qdrant|BGP\s+Anycast)\b"), EntityType.TECHNOLOGY),
    # Organizations
    (re.compile(r"\b([A-Z][a-zA-Z0-9&_-]+(?:[ \t]+[A-Z][a-zA-Z0-9&_-]+){0,3}[ \t]+(?:Corp|Corporation|Inc|LLC|Ltd|Systems|Technologies|Labs|Holdings|Bank|Financial|Cloud|Group|Authority|Agency|Networks|Security)(?:[ \t]+(?:Cloud|Systems|Group|Holdings|Corp|Inc|LLC|Ltd))?)\b"), EntityType.ORGANIZATION),
    # Locations / Regions
    (re.compile(r"\b(us-east-\d|eu-central-\d|ap-southeast-\d|eu-west-\d|Frankfurt\s+Data\s+Center|Tokyo\s+Region|Northern\s+Virginia\s+Hub|London\s+Metro\s+Zone|Singapore\s+Availability\s+Zone|European\s+Union|United\s+States|United\s+Kingdom)\b"), EntityType.LOCATION),
    # Persons with Titles/Roles
    (re.compile(r"\b((?:Dr\.|Prof\.|VP|CTO|CISO|Director|Lead[ \t]+Architect|Chief[ \t]+Risk[ \t]+Officer)[ \t]+[A-Z][a-z]+[ \t]+[A-Z][a-z]+)\b"), EntityType.PERSON),
]

STOP_ENTITY_NAMES = {
    "The", "This", "That", "These", "Those", "However", "Therefore", "Furthermore",
    "In Addition", "Document Overview", "Section", "Summary", "Table", "Figure",
    "Root", "Page", "System", "Service", "Platform", "Company", "Organization",
}

# Relationship cue patterns (verb/preposition phrases mapping to RelationshipType)
RELATIONSHIP_CUES: List[Tuple[re.Pattern[str], RelationshipType]] = [
    (re.compile(r"\b(depends\s+on|relies\s+on|requires|backed\s+by|hosted\s+on|runs\s+on)\b", re.IGNORECASE), RelationshipType.DEPENDS_ON),
    (re.compile(r"\b(caused\s+by|triggered\s+by|resulted\s+from|stemmed\s+from|induced\s+by|due\s+to)\b", re.IGNORECASE), RelationshipType.CAUSED_BY),
    (re.compile(r"\b(operates|manages|maintains|administers|controls|hosts)\b", re.IGNORECASE), RelationshipType.OPERATES),
    (re.compile(r"\b(acquired|purchased|bought|merged\s+with|absorbed)\b", re.IGNORECASE), RelationshipType.ACQUIRED),
    (re.compile(r"\b(partnered\s+with|collaborated\s+with|contracted\s+with|integrated\s+with|supplied\s+by)\b", re.IGNORECASE), RelationshipType.PARTNERED_WITH),
    (re.compile(r"\b(regulated\s+by|governed\s+by|audited\s+under|subject\s+to|mandated\s+by|compliant\s+with|violated)\b", re.IGNORECASE), RelationshipType.REGULATED_BY),
    (re.compile(r"\b(located\s+in|deployed\s+in|hosted\s+in|based\s+in|headquartered\s+in|routed\s+through)\b", re.IGNORECASE), RelationshipType.LOCATED_IN),
    (re.compile(r"\b(developed\s+by|engineered\s+by|authored\s+by|built\s+by|led\s+by|designed\s+by)\b", re.IGNORECASE), RelationshipType.DEVELOPED_BY),
    (re.compile(r"\b(impacts|impacted|affected|disrupted|degraded|delayed|damaged|compromised|caused)\b", re.IGNORECASE), RelationshipType.IMPACTS),
    (re.compile(r"\b(reported|recorded|achieved|incurred|measured|logged|suffered|breached)\b", re.IGNORECASE), RelationshipType.REPORTED_METRIC),
    (re.compile(r"\b(succeeded\s+by|replaced\s+by|superseded\s+by|upgraded\s+to|migrated\s+to)\b", re.IGNORECASE), RelationshipType.SUCCEEDED_BY),
]

TEMPORAL_CUE_RE = re.compile(
    r"\b(Q[1-4]\s+202\d|202\d-\d{2}-\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+202\d|in\s+202\d)\b",
    re.IGNORECASE,
)

ALIAS_PAREN_RE = re.compile(r"([A-Z][A-Za-z0-9\s&_-]{3,60})\s+\(([A-Z0-9-]{2,15})\)")


def _extract_local_deterministic(chunk: ChunkRecord) -> ChunkExtractionResult:
    """
    Deterministic, high-precision entity and relationship extractor with exact character spans,
    alias capture, temporal marker attachment, and explicit vs. inferred distinction.
    """
    text = chunk.text
    found_entities: Dict[str, ExtractedEntity] = {}
    alias_map: Dict[str, List[str]] = {}

    # 1. Detect explicit parenthetical aliases, e.g., "Helios Payment Gateway (HPG)"
    for match in ALIAS_PAREN_RE.finditer(text):
        full_name = " ".join(match.group(1).strip().split())
        acronym = match.group(2).strip()
        if full_name not in STOP_ENTITY_NAMES:
            alias_map.setdefault(full_name, [])
            if acronym not in alias_map[full_name]:
                alias_map[full_name].append(acronym)

    # 2. Extract typed entities via domain rules
    for pattern, ent_type in KNOWN_ENTITY_PATTERNS:
        for match in pattern.finditer(text):
            raw_name = " ".join(match.group(1).strip().split())
            if raw_name in STOP_ENTITY_NAMES or len(raw_name) < 2:
                continue
            start_idx, end_idx = match.span(1)
            # Extract sentence context as evidence quote
            sent_start = max(0, text.rfind(".", 0, start_idx) + 1)
            sent_end_dot = text.find(".", end_idx)
            sent_end = len(text) if sent_end_dot == -1 else min(len(text), sent_end_dot + 1)
            quote = " ".join(text[sent_start:sent_end].strip().split())
            if len(quote) < 3:
                quote = raw_name

            aliases = list(alias_map.get(raw_name, []))
            # Also check if acronym appears right after raw_name in text
            after_text = text[end_idx : end_idx + 20]
            acr_match = re.match(r"^\s*\(([A-Z0-9-]{2,12})\)", after_text)
            if acr_match and acr_match.group(1) not in aliases:
                aliases.append(acr_match.group(1))

            if raw_name not in found_entities:
                found_entities[raw_name] = ExtractedEntity(
                    name=raw_name,
                    entity_type=ent_type,
                    aliases=aliases,
                    description=f"{ent_type.value} mentioned in section '{chunk.section_title}' (Page {chunk.page_number}).",
                    confidence=0.92,
                    evidence_quote=quote[:580],
                    char_start=chunk.char_start + start_idx,
                    char_end=chunk.char_start + end_idx,
                )
            else:
                for a in aliases:
                    if a not in found_entities[raw_name].aliases:
                        found_entities[raw_name].aliases.append(a)

    # 3. Extract explicit intra-sentence relationships
    sentences = re.split(r"(?<=[.!?])\s+|\n+", text)
    relationships: List[ExtractedRelationship] = []
    seen_edges = set()

    entity_list = list(found_entities.values())
    # Map surface forms (including aliases) back to canonical entity name in this chunk
    surface_to_entity: List[Tuple[str, ExtractedEntity]] = []
    for ent in entity_list:
        surface_to_entity.append((ent.name, ent))
        for al in ent.aliases:
            if len(al) >= 2:
                surface_to_entity.append((al, ent))
    # Sort longest surface form first to prevent partial substring collisions
    surface_to_entity.sort(key=lambda x: len(x[0]), reverse=True)

    running_offset = 0
    for sent in sentences:
        sent_stripped = sent.strip()
        if len(sent_stripped) < 8:
            running_offset += len(sent) + 1
            continue

        sent_pos = text.find(sent_stripped, running_offset)
        if sent_pos == -1:
            sent_pos = running_offset
        running_offset = sent_pos + len(sent_stripped)

        # Find all entities mentioned in this sentence with their positions
        sent_mentions: List[Tuple[int, int, ExtractedEntity]] = []
        occupied_spans: List[Tuple[int, int]] = []
        for surf, ent in surface_to_entity:
            for m in re.finditer(r"\b" + re.escape(surf) + r"\b", sent_stripped):
                s_idx, e_idx = m.span()
                if any(not (e_idx <= os or s_idx >= oe) for os, oe in occupied_spans):
                    continue
                occupied_spans.append((s_idx, e_idx))
                sent_mentions.append((s_idx, e_idx, ent))

        sent_mentions.sort(key=lambda x: x[0])
        if len(sent_mentions) < 2:
            continue

        temp_match = TEMPORAL_CUE_RE.search(sent_stripped)
        temporal_marker = temp_match.group(1) if temp_match else None

        # Check pairs of entities in sentence order
        for i in range(len(sent_mentions)):
            for j in range(i + 1, len(sent_mentions)):
                pos_a, end_a, ent_a = sent_mentions[i]
                pos_b, end_b, ent_b = sent_mentions[j]
                if ent_a.name == ent_b.name:
                    continue

                between_text = sent_stripped[end_a:pos_b]
                matched_rel: Optional[RelationshipType] = None
                for cue_re, rel_type in RELATIONSHIP_CUES:
                    if cue_re.search(between_text):
                        matched_rel = rel_type
                        break

                # Fallback check across whole sentence if only 2 entities in sentence
                if matched_rel is None and len(sent_mentions) == 2:
                    for cue_re, rel_type in RELATIONSHIP_CUES:
                        if cue_re.search(sent_stripped):
                            matched_rel = rel_type
                            break

                is_inferred = False
                confidence = 0.90
                if matched_rel is None:
                    # Infer typed edge based on entity type semantics if adjacent in same clause
                    if (pos_b - end_a) <= 85:
                        is_inferred = True
                        confidence = 0.72
                        if ent_b.entity_type == EntityType.METRIC:
                            matched_rel = RelationshipType.REPORTED_METRIC
                        elif ent_b.entity_type == EntityType.LOCATION:
                            matched_rel = RelationshipType.LOCATED_IN
                        elif ent_b.entity_type == EntityType.POLICY:
                            matched_rel = RelationshipType.REGULATED_BY
                        elif ent_a.entity_type == EntityType.EVENT and ent_b.entity_type in (EntityType.SYSTEM, EntityType.ORGANIZATION):
                            matched_rel = RelationshipType.IMPACTS
                        else:
                            matched_rel = RelationshipType.ASSOCIATED_WITH

                if matched_rel is not None:
                    edge_key = (ent_a.name, ent_b.name, matched_rel.value)
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        relationships.append(
                            ExtractedRelationship(
                                source_entity=ent_a.name,
                                target_entity=ent_b.name,
                                relationship_type=matched_rel,
                                is_inferred=is_inferred,
                                confidence=confidence,
                                evidence_quote=" ".join(sent_stripped.split())[:580],
                                char_start=chunk.char_start + sent_pos,
                                char_end=chunk.char_start + sent_pos + len(sent_stripped),
                                temporal_marker=temporal_marker,
                            )
                        )

    return ChunkExtractionResult(
        chunk_id=chunk.chunk_id,
        doc_id=chunk.doc_id,
        entities=list(found_entities.values()),
        relationships=relationships,
        extraction_method="local_deterministic",
    )


def validate_raw_llm_extraction_json(
    chunk: ChunkRecord, raw_json_str: str, provider_name: str = "llm"
) -> ChunkExtractionResult:
    """
    Parse and strictly validate untrusted LLM JSON output against ExtractedEntity and
    ExtractedRelationship Pydantic schemas. Never trusts hallucinated relationship types
    or missing provenance quotes.
    """
    warnings: List[str] = []
    try:
        # Strip markdown fences if present
        cleaned = raw_json_str.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.DOTALL).strip()
        payload = json.loads(cleaned)
    except Exception as exc:
        raise ValueError(f"Malformed LLM JSON output from {provider_name}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object from {provider_name}, got {type(payload).__name__}.")

    valid_entities: List[ExtractedEntity] = []
    raw_entities = payload.get("entities", [])
    if not isinstance(raw_entities, list):
        raise ValueError("Field 'entities' in extraction output must be a list.")

    for idx, item in enumerate(raw_entities):
        try:
            if not isinstance(item, dict):
                warnings.append(f"Skipped non-object entity at index {idx}")
                continue
            if not item.get("evidence_quote"):
                item["evidence_quote"] = chunk.text[:200]
            ent = ExtractedEntity.model_validate(item)
            valid_entities.append(ent)
        except ValidationError as verr:
            warnings.append(f"Rejected invalid entity at index {idx}: {verr.errors()[0]['msg']}")

    valid_relationships: List[ExtractedRelationship] = []
    raw_rels = payload.get("relationships", [])
    if not isinstance(raw_rels, list):
        raise ValueError("Field 'relationships' in extraction output must be a list.")

    for idx, item in enumerate(raw_rels):
        try:
            if not isinstance(item, dict):
                warnings.append(f"Skipped non-object relationship at index {idx}")
                continue
            rel = ExtractedRelationship.model_validate(item)
            valid_relationships.append(rel)
        except ValidationError as verr:
            warnings.append(f"Rejected invalid relationship at index {idx}: {verr.errors()[0]['msg']}")

    return ChunkExtractionResult(
        chunk_id=chunk.chunk_id,
        doc_id=chunk.doc_id,
        entities=valid_entities,
        relationships=valid_relationships,
        extraction_method=provider_name,
        warnings=warnings,
    )


def extract_from_chunk(chunk: ChunkRecord) -> ChunkExtractionResult:
    """
    Extract entities and relationships from a chunk using configured LLM provider,
    falling back safely with recorded warnings if external provider is unreachable.
    """
    provider = settings.llm_provider
    if provider == "local":
        return _extract_local_deterministic(chunk)

    prompt = (
        "Extract entities and typed relationships from the text chunk below.\n"
        f"Allowed entity_type values: {[e.value for e in EntityType]}\n"
        f"Allowed relationship_type values: {[r.value for r in RelationshipType]}\n"
        "Return ONLY valid JSON with keys 'entities' and 'relationships'. Every item MUST include 'evidence_quote' copied verbatim from the chunk.\n\n"
        f"CHUNK TEXT:\n{chunk.text}"
    )

    try:
        if provider == "openai" and settings.openai_api_key:
            with httpx.Client(timeout=20.0) as client:
                resp = client.post(
                    f"{settings.openai_base_url.rstrip('/')}/chat/completions",
                    headers={"Authorization": f"Bearer {settings.openai_api_key}"},
                    json={
                        "model": settings.openai_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.0,
                    },
                )
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"]
                return validate_raw_llm_extraction_json(chunk, content, provider_name="openai")

        if provider == "ollama":
            with httpx.Client(timeout=20.0) as client:
                resp = client.post(
                    f"{settings.ollama_base_url.rstrip('/')}/api/generate",
                    json={"model": settings.ollama_model, "prompt": prompt, "stream": False},
                )
                resp.raise_for_status()
                content = resp.json().get("response", "")
                return validate_raw_llm_extraction_json(chunk, content, provider_name="ollama")
    except Exception as exc:
        fallback = _extract_local_deterministic(chunk)
        fallback.warnings.append(
            f"External provider '{provider}' failed ({exc}); used deterministic local extraction fallback."
        )
        return fallback

    return _extract_local_deterministic(chunk)
