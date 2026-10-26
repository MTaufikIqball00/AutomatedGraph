"""Entity resolution: canonical normalization, alias merging, and uncertain match tracking."""
from __future__ import annotations

import hashlib
import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Set, Tuple

from backend.schemas import EntityType, ExtractedEntity

CORPORATE_SUFFIX_RE = re.compile(
    r"\b(corporation|corp\.?|inc\.?|llc|ltd\.?|limited|plc)\s*$",
    re.IGNORECASE,
)

VERSION_OR_NUMBER_RE = re.compile(r"\b(v?\d+(?:\.\d+)*|us-east-\d|eu-central-\d|ap-southeast-\d|q[1-4]|type\s+i+|wave\s+\d+|inc-\d{4}-\d+|out-\d{4}-\d+|aud-\d{4}-\d+)\b", re.IGNORECASE)

GEO_SUFFIX_TOKENS = {"us", "uk", "eu", "apac", "emea", "north", "south", "east", "west", "tokyo", "frankfurt", "london", "singapore"}


def normalize_entity_key(name: str, entity_type: EntityType) -> str:
    """
    Produce a canonical lookup key for an entity name.
    Strips purely legal suffixes (Inc., Corp.) for ORGANIZATIONs while preserving meaningful
    distinguishing tokens (regions, versions, numbers).
    """
    cleaned = " ".join(name.strip().lower().split())
    cleaned = re.sub(r"['\"`]", "", cleaned)
    if entity_type == EntityType.ORGANIZATION:
        stripped = CORPORATE_SUFFIX_RE.sub("", cleaned).strip(" ,.-")
        if len(stripped) >= 3:
            cleaned = stripped
    return cleaned


def compute_entity_id(tenant_id: str, normalized_key: str, entity_type: EntityType) -> str:
    """Compute a deterministic entity ID from tenant, normalized key, and entity type."""
    raw = f"{tenant_id}::{entity_type.value}::{normalized_key}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:14]
    return f"ent-{digest}"


def compute_name_similarity(name_a: str, name_b: str) -> float:
    """Compute hybrid character + token Jaccard similarity between two entity names."""
    norm_a = " ".join(name_a.lower().split())
    norm_b = " ".join(name_b.lower().split())
    if norm_a == norm_b:
        return 1.0
    seq_sim = SequenceMatcher(None, norm_a, norm_b).ratio()
    tokens_a = set(re.findall(r"[a-z0-9]+", norm_a))
    tokens_b = set(re.findall(r"[a-z0-9]+", norm_b))
    if not tokens_a or not tokens_b:
        return seq_sim
    jaccard = len(tokens_a & tokens_b) / len(tokens_a | tokens_b)
    return round(0.6 * seq_sim + 0.4 * jaccard, 4)


def has_conflicting_distinguishers(name_a: str, name_b: str) -> Optional[str]:
    """
    Detect if two similar entity names have distinct version numbers, incident codes,
    or geographic qualifiers that must NEVER be merged automatically.
    """
    nums_a = {m.group(0).lower() for m in VERSION_OR_NUMBER_RE.finditer(name_a)}
    nums_b = {m.group(0).lower() for m in VERSION_OR_NUMBER_RE.finditer(name_b)}
    if nums_a and nums_b and nums_a != nums_b:
        return f"Distinct version/identifier tokens ({sorted(nums_a)} vs {sorted(nums_b)})"

    tokens_a = set(re.findall(r"[a-z0-9]+", name_a.lower())) & GEO_SUFFIX_TOKENS
    tokens_b = set(re.findall(r"[a-z0-9]+", name_b.lower())) & GEO_SUFFIX_TOKENS
    if tokens_a and tokens_b and tokens_a != tokens_b:
        return f"Distinct regional qualifiers ({sorted(tokens_a)} vs {sorted(tokens_b)})"

    return None


def generate_acronym(name: str) -> str:
    """Generate uppercase acronym from multi-word entity name (ignoring stop prepositions)."""
    words = [w for w in re.findall(r"[A-Za-z0-9]+", name) if w.lower() not in {"of", "the", "and", "for", "in"}]
    if len(words) < 2:
        return ""
    return "".join(w[0].upper() for w in words)


class EntityResolver:
    """
    Resolves extracted entities against existing graph entities within a tenant scope:
    - Merges exact normalized keys and verified aliases/acronyms.
    - Merges very high-confidence spelling variants (>= 0.93) when no conflicting distinguishers exist.
    - Tracks ambiguous/uncertain matches (0.72 <= similarity < 0.93 or conflicting distinguishers)
      without merging distinct entities.
    """

    def __init__(self, existing_entities: List[Dict[str, object]], tenant_id: str) -> None:
        self.tenant_id = tenant_id
        # Map (entity_type, normalized_key) -> entity_record
        self.by_key: Dict[Tuple[str, str], Dict[str, object]] = {}
        # Map alias_lower -> List[entity_record]
        self.by_alias: Dict[str, List[Dict[str, object]]] = {}
        self.entities_by_id: Dict[str, Dict[str, object]] = {}

        for ent in existing_entities:
            self._index_entity(ent)

    def _index_entity(self, ent: Dict[str, object]) -> None:
        ent_id = str(ent["entity_id"])
        ent_type = str(ent["entity_type"])
        norm_key = str(ent["normalized_key"])
        canon_name = str(ent["canonical_name"])
        aliases: List[str] = list(ent.get("aliases", []))  # type: ignore[arg-type]

        self.entities_by_id[ent_id] = ent
        self.by_key[(ent_type, norm_key)] = ent

        all_forms = {canon_name.lower(), norm_key} | {a.lower().strip() for a in aliases if a}
        acr = generate_acronym(canon_name)
        if len(acr) >= 3:
            all_forms.add(acr.lower())

        for form in all_forms:
            lst = self.by_alias.setdefault(form, [])
            if all(x["entity_id"] != ent_id for x in lst):
                lst.append(ent)

    def resolve(
        self, extracted: ExtractedEntity, doc_id: str
    ) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
        """
        Resolve an ExtractedEntity.
        Returns (resolved_entity_dict, list_of_uncertain_match_dicts).
        """
        ent_type = extracted.entity_type.value
        norm_key = normalize_entity_key(extracted.name, extracted.entity_type)
        uncertain_records: List[Dict[str, object]] = []

        # 1. Exact normalized key + type match
        if (ent_type, norm_key) in self.by_key:
            target = self.by_key[(ent_type, norm_key)]
            self._merge_aliases_and_description(target, extracted)
            return target, uncertain_records

        # 2. Exact alias match with compatible entity type
        candidate_forms = [extracted.name.lower().strip(), norm_key] + [
            a.lower().strip() for a in extracted.aliases if a.strip()
        ]
        for form in candidate_forms:
            matches = self.by_alias.get(form, [])
            same_type = [m for m in matches if m["entity_type"] == ent_type]
            if len(same_type) == 1:
                target = same_type[0]
                conflict = has_conflicting_distinguishers(str(target["canonical_name"]), extracted.name)
                if not conflict:
                    self._merge_aliases_and_description(target, extracted)
                    return target, uncertain_records

        # 3. Compare similarity against existing entities of the same type
        best_match: Optional[Dict[str, object]] = None
        best_score = 0.0

        for (k_type, _), existing in self.by_key.items():
            if k_type != ent_type:
                continue
            existing_name = str(existing["canonical_name"])
            sim = compute_name_similarity(extracted.name, existing_name)
            if sim > best_score:
                best_score = sim
                best_match = existing

        new_ent_id = compute_entity_id(self.tenant_id, norm_key, extracted.entity_type)

        if best_match is not None and best_score >= 0.72:
            existing_name = str(best_match["canonical_name"])
            conflict = has_conflicting_distinguishers(existing_name, extracted.name)
            if conflict is None and best_score >= 0.93:
                # High-confidence variant without conflicting distinguishers -> safe merge
                self._merge_aliases_and_description(best_match, extracted)
                return best_match, uncertain_records
            else:
                # Record as an uncertain match and DO NOT merge distinct entities
                reason = conflict or f"Moderate surface similarity ({best_score:.2f}) below auto-merge threshold (0.93)"
                match_hash = hashlib.sha256(
                    f"{self.tenant_id}::{best_match['entity_id']}::{new_ent_id}".encode("utf-8")
                ).hexdigest()[:12]
                uncertain_records.append(
                    {
                        "match_id": f"unc-{match_hash}",
                        "tenant_id": self.tenant_id,
                        "entity_a_id": str(best_match["entity_id"]),
                        "entity_a_name": existing_name,
                        "entity_b_id": new_ent_id,
                        "entity_b_name": extracted.name,
                        "entity_type": ent_type,
                        "similarity_score": best_score,
                        "reason": reason,
                        "doc_id": doc_id,
                    }
                )

        # 4. Create new canonical entity
        aliases_set: Set[str] = {a.strip() for a in extracted.aliases if a.strip() and a.strip() != extracted.name}
        new_entity: Dict[str, object] = {
            "entity_id": new_ent_id,
            "tenant_id": self.tenant_id,
            "canonical_name": extracted.name,
            "normalized_key": norm_key,
            "entity_type": ent_type,
            "aliases": sorted(aliases_set),
            "description": extracted.description,
            "confidence": extracted.confidence,
        }
        self._index_entity(new_entity)
        return new_entity, uncertain_records

    def _merge_aliases_and_description(
        self, target: Dict[str, object], extracted: ExtractedEntity
    ) -> None:
        aliases: List[str] = list(target.get("aliases", []))  # type: ignore[arg-type]
        canon = str(target["canonical_name"])
        if extracted.name != canon and extracted.name not in aliases:
            aliases.append(extracted.name)
        for a in extracted.aliases:
            if a and a != canon and a not in aliases:
                aliases.append(a)
        target["aliases"] = sorted(set(aliases))
        if len(extracted.description) > len(str(target.get("description", ""))):
            target["description"] = extracted.description
        target["confidence"] = max(float(target.get("confidence", 0.85)), extracted.confidence)  # type: ignore[arg-type]
        self._index_entity(target)
