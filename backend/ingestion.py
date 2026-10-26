"""Document ingestion, parsing, structure preservation, and deterministic chunking."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from typing import Any, Dict, List, Tuple
from pypdf import PdfReader

from backend.schemas import ChunkRecord


PAGE_MARKER_RE = re.compile(r"^\s*\[Page\s+(\d+)\]\s*$", re.IGNORECASE)
HEADING_RE = re.compile(r"^(#{1,4})\s+(.+?)\s*$")
UPPER_HEADING_RE = re.compile(r"^([A-Z][A-Z0-9\s,&/-]{4,65}):?\s*$")


def compute_sha256(raw_bytes: bytes) -> str:
    """Return hex SHA-256 digest of raw file bytes."""
    return hashlib.sha256(raw_bytes).hexdigest()


def compute_doc_id(tenant_id: str, filename: str) -> str:
    """Compute a deterministic document ID scoped to tenant and normalized filename."""
    norm_name = filename.strip().lower()
    digest = hashlib.sha256(f"{tenant_id}::{norm_name}".encode("utf-8")).hexdigest()[:16]
    return f"doc-{digest}"


def compute_chunk_id(doc_id: str, chunk_index: int, text: str) -> str:
    """Compute a stable, deterministic chunk ID from document ID, index, and content hash."""
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return f"chk-{doc_id[4:12]}-{chunk_index:04d}-{text_hash}"


def decode_text_bytes(raw_bytes: bytes) -> str:
    """Decode text bytes safely using UTF-8 or UTF-8-SIG, rejecting malformed binary streams."""
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            decoded = raw_bytes.decode(encoding)
            # Verify printable ratio to avoid garbage binary decoding under latin-1
            printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
            if len(decoded) > 0 and (printable / len(decoded)) < 0.85:
                continue
            return decoded
        except UnicodeDecodeError:
            continue
    raise ValueError("Unable to decode document text with supported encodings (UTF-8).")


def extract_text_from_file(
    filename: str, raw_bytes: bytes
) -> Tuple[str, Dict[str, Any]]:
    """Extract structured text and source metadata from supported file formats."""
    ext = "." + filename.lower().strip().rsplit(".", 1)[-1] if "." in filename else ".txt"
    metadata: Dict[str, Any] = {"format": ext.lstrip(".")}

    if ext in {".txt", ".md"}:
        text = decode_text_bytes(raw_bytes)
        metadata["line_count"] = len(text.splitlines())
        return text, metadata

    if ext == ".pdf":
        try:
            reader = PdfReader(io.BytesIO(raw_bytes))
            pages_text: List[str] = []
            for idx, page in enumerate(reader.pages, start=1):
                page_str = (page.extract_text() or "").strip()
                if page_str:
                    pages_text.append(f"[Page {idx}]\n{page_str}")
            full_text = "\n\n".join(pages_text)
            if not full_text.strip():
                raise ValueError("PDF contains no extractable text (may be scanned images only).")
            metadata["page_count"] = len(reader.pages)
            return full_text, metadata
        except Exception as exc:
            raise ValueError(f"Failed to parse PDF document '{filename}': {exc}") from exc

    if ext == ".json":
        try:
            decoded = decode_text_bytes(raw_bytes)
            data = json.loads(decoded)
            lines: List[str] = ["# JSON Document Content"]
            if isinstance(data, dict):
                metadata["top_level_keys"] = list(data.keys())[:20]
                for k, v in data.items():
                    lines.append(f"## {k}\n{json.dumps(v, ensure_ascii=False, indent=2) if isinstance(v, (dict, list)) else v}")
            elif isinstance(data, list):
                metadata["record_count"] = len(data)
                for idx, item in enumerate(data, start=1):
                    lines.append(f"## Record {idx}\n{json.dumps(item, ensure_ascii=False)}")
            else:
                lines.append(str(data))
            return "\n\n".join(lines), metadata
        except Exception as exc:
            raise ValueError(f"Failed to parse JSON document '{filename}': {exc}") from exc

    if ext == ".csv":
        try:
            decoded = decode_text_bytes(raw_bytes)
            reader = csv.reader(io.StringIO(decoded))
            rows = list(reader)
            if not rows:
                raise ValueError("CSV file contains no rows.")
            headers = rows[0]
            metadata["columns"] = headers
            metadata["row_count"] = max(0, len(rows) - 1)
            lines = ["# CSV Tabular Data"]
            for idx, row in enumerate(rows[1:], start=1):
                pairs = [f"{headers[i] if i < len(headers) else f'col_{i}'}: {val}" for i, val in enumerate(row)]
                lines.append(f"Row {idx} — " + "; ".join(pairs))
            return "\n\n".join(lines), metadata
        except Exception as exc:
            raise ValueError(f"Failed to parse CSV document '{filename}': {exc}") from exc

    raise ValueError(f"Unsupported file format '{ext}'.")


def clean_text_preserving_structure(raw_text: str) -> str:
    """Normalize line endings and whitespace while preserving section headers and paragraphs."""
    text = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    # Remove non-printable control characters except newline and tab
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ch.isprintable())
    # Collapse 3+ consecutive blank lines into double newline
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def preprocess_and_chunk_document(
    doc_id: str,
    tenant_id: str,
    raw_text: str,
    chunk_size_chars: int = 900,
    chunk_overlap_chars: int = 150,
) -> List[ChunkRecord]:
    """
    Structure-aware document chunker.
    Tracks [Page N] markers and Markdown/uppercase section headings, splits on paragraph/sentence
    boundaries where possible, and assigns deterministic chunk IDs with exact character spans.
    """
    cleaned = clean_text_preserving_structure(raw_text)
    if not cleaned:
        raise ValueError("Document contains no meaningful text after preprocessing.")

    lines = cleaned.split("\n")
    current_page = 1
    current_section = "Document Overview"

    # Build annotated blocks with (page, section, text, char_start, char_end)
    blocks: List[Tuple[int, str, str, int, int]] = []
    cursor = 0
    para_lines: List[str] = []
    para_start = 0

    def flush_paragraph(end_pos: int) -> None:
        nonlocal para_lines
        if para_lines:
            para_text = "\n".join(para_lines).strip()
            if para_text:
                blocks.append((current_page, current_section, para_text, para_start, end_pos))
            para_lines = []

    for line in lines:
        line_len = len(line) + 1  # +1 for newline
        page_match = PAGE_MARKER_RE.match(line)
        if page_match:
            flush_paragraph(cursor)
            current_page = int(page_match.group(1))
            cursor += line_len
            para_start = cursor
            continue

        heading_match = HEADING_RE.match(line)
        if heading_match:
            flush_paragraph(cursor)
            current_section = heading_match.group(2).strip()
            para_start = cursor
            para_lines.append(line)
            cursor += line_len
            continue

        upper_match = UPPER_HEADING_RE.match(line.strip())
        if upper_match and len(line.strip().split()) <= 8 and not line.strip().endswith("."):
            flush_paragraph(cursor)
            current_section = upper_match.group(1).strip()
            para_start = cursor
            para_lines.append(line)
            cursor += line_len
            continue

        if not line.strip():
            flush_paragraph(cursor)
            cursor += line_len
            para_start = cursor
        else:
            if not para_lines:
                para_start = cursor
            para_lines.append(line)
            cursor += line_len

    flush_paragraph(cursor)

    # Group blocks into chunks respecting chunk_size_chars and section boundaries
    chunks: List[ChunkRecord] = []
    buf_texts: List[str] = []
    buf_page = 1
    buf_section = "Document Overview"
    buf_start = 0
    buf_end = 0

    def emit_chunk() -> None:
        if not buf_texts:
            return
        combined = "\n\n".join(buf_texts).strip()
        if not combined:
            return
        idx = len(chunks)
        c_id = compute_chunk_id(doc_id, idx, combined)
        tokens = len(re.findall(r"\S+", combined))
        chunks.append(
            ChunkRecord(
                chunk_id=c_id,
                doc_id=doc_id,
                tenant_id=tenant_id,
                chunk_index=idx,
                page_number=buf_page,
                section_title=buf_section,
                text=combined,
                char_start=buf_start,
                char_end=buf_end,
                token_count=tokens,
            )
        )

    for page, section, b_text, b_start, b_end in blocks:
        # If single block exceeds chunk_size_chars, split by sentences
        if len(b_text) > chunk_size_chars:
            if buf_texts:
                emit_chunk()
                buf_texts = []
            sentences = re.split(r"(?<=[.!?])\s+", b_text)
            sub_buf = ""
            sub_start = b_start
            for sent in sentences:
                if len(sub_buf) + len(sent) + 1 <= chunk_size_chars or not sub_buf:
                    sub_buf = f"{sub_buf} {sent}".strip() if sub_buf else sent
                else:
                    buf_page = page
                    buf_section = section
                    buf_start = sub_start
                    buf_end = sub_start + len(sub_buf)
                    buf_texts = [sub_buf]
                    emit_chunk()
                    # Overlap tail
                    overlap_tail = sub_buf[-chunk_overlap_chars:] if chunk_overlap_chars > 0 else ""
                    sub_start = buf_end - len(overlap_tail)
                    sub_buf = f"{overlap_tail} {sent}".strip()
            if sub_buf:
                buf_page = page
                buf_section = section
                buf_start = sub_start
                buf_end = b_end
                buf_texts = [sub_buf]
                emit_chunk()
                buf_texts = []
            continue

        current_len = sum(len(t) for t in buf_texts) + (2 * max(0, len(buf_texts) - 1))
        if buf_texts and (current_len + len(b_text) + 2 > chunk_size_chars):
            emit_chunk()
            # Carry overlap if within the same section
            if chunk_overlap_chars > 0 and buf_section == section and buf_texts:
                last_block = buf_texts[-1]
                overlap_str = last_block[-chunk_overlap_chars:].strip()
                buf_texts = [overlap_str, b_text] if overlap_str else [b_text]
            else:
                buf_texts = [b_text]
            buf_page = page
            buf_section = section
            buf_start = b_start
            buf_end = b_end
        else:
            if not buf_texts:
                buf_page = page
                buf_section = section
                buf_start = b_start
            buf_texts.append(b_text)
            buf_end = b_end

    if buf_texts:
        emit_chunk()

    return chunks
