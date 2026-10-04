"""
Jane AI Layer — Deterministic Evidence Chunker
Divides scraped page text into traceable, sentence-bounded chunks with exact
character offsets, deterministic IDs, and SHA-256 hashes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
from typing import Any, Dict, List, Optional

TARGET_CHUNK_SIZE = 750
MIN_CHUNK_SIZE = 120


@dataclass
class EvidenceChunk:
    chunk_id: str
    page_id: str
    investigation_id: str
    url: str
    text: str
    char_start: int
    char_end: int
    sha256: str
    retrieved_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def chunk_text(
    text: str,
    page_id: str,
    url: str = "",
    investigation_id: str = "",
    retrieved_at: str = "",
    target_size: int = TARGET_CHUNK_SIZE,
) -> List[EvidenceChunk]:
    """
    Slices raw text into sentence-bounded chunks with character offsets.
    Ensures zero character drift and traceable provenance.
    """
    if not text or not text.strip():
        return []

    # Split roughly on sentence boundaries while keeping track of indices
    sentence_spans: List[tuple[int, int]] = []
    for match in re.finditer(r"(?:[^\n.!?]+[\n.!?]+|\S+$)", text):
        s = match.start()
        e = match.end()
        if e > s:
            sentence_spans.append((s, e))

    if not sentence_spans:
        sentence_spans = [(0, len(text))]

    chunks: List[EvidenceChunk] = []
    chunk_idx = 1

    curr_start = 0
    curr_end = 0

    for s, e in sentence_spans:
        if curr_end == 0:
            curr_start = s
            curr_end = e
        elif (e - curr_start) <= target_size:
            curr_end = e
        else:
            # Emit current chunk
            chunk_slice = text[curr_start:curr_end].strip()
            if len(chunk_slice) >= MIN_CHUNK_SIZE or not chunks:
                ch_hash = hashlib.sha256(chunk_slice.encode("utf-8")).hexdigest()
                cid = f"{page_id[:8]}-c{chunk_idx:02d}"
                chunks.append(EvidenceChunk(
                    chunk_id=cid,
                    page_id=page_id,
                    investigation_id=investigation_id,
                    url=url,
                    text=chunk_slice,
                    char_start=curr_start,
                    char_end=curr_end,
                    sha256=ch_hash,
                    retrieved_at=retrieved_at,
                ))
                chunk_idx += 1
            curr_start = s
            curr_end = e

    # Last remaining chunk
    if curr_end > curr_start:
        chunk_slice = text[curr_start:curr_end].strip()
        if chunk_slice:
            ch_hash = hashlib.sha256(chunk_slice.encode("utf-8")).hexdigest()
            cid = f"{page_id[:8]}-c{chunk_idx:02d}"
            chunks.append(EvidenceChunk(
                chunk_id=cid,
                page_id=page_id,
                investigation_id=investigation_id,
                url=url,
                text=chunk_slice,
                char_start=curr_start,
                char_end=curr_end,
                sha256=ch_hash,
                retrieved_at=retrieved_at,
            ))

    return chunks
