"""
Jane Pipeline — Query Planner & Fanout Engine
Expands user hunt query into bounded, focused search phrases.
Uses OpenCode LLM if reachable; otherwise fast deterministic fallback.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("jane.pipeline.query_planner")

OPENCODE_URL = "http://127.0.0.1:4096"
MAX_FANOUT_QUERIES = 8
FANOUT_PROMPT_VERSION = "v1"
INTERNAL_FANOUT_PROMPT = """Generate high-signal, distinct search queries for an authorized investigation of hidden services. Preserve the core subject, add exact phrases, aliases, locations, slang, and domain terminology where useful. Avoid generic filler, duplicate queries, and unsupported facts. Return only JSON with a queries array; each item must contain text and purpose."""


@dataclass
class PlannedQuery:
    text: str
    purpose: str  # "exact", "location", "synonym", "domain_terminology", "quoted"


@dataclass
class QueryPlan:
    original_query: str
    queries: List[PlannedQuery]
    generation_source: str = "deterministic_fallback"
    prompt_version: str = FANOUT_PROMPT_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_query": self.original_query,
            "queries": [asdict(q) for q in self.queries],
            "generation_source": self.generation_source,
            "prompt_version": self.prompt_version,
        }


def _deterministic_fanout(query: str, max_queries: int = MAX_FANOUT_QUERIES) -> List[PlannedQuery]:
    """Pure stdlib deterministic expansions when LLM is unavailable."""
    q_clean = query.strip()
    words = q_clean.split()
    results: List[PlannedQuery] = []
    seen: set[str] = set()

    def add(text: str, purpose: str):
        t = text.strip()
        if t and t.lower() not in seen and len(results) < max_queries:
            seen.add(t.lower())
            results.append(PlannedQuery(text=t, purpose=purpose))

    # 1. Exact
    add(q_clean, "exact")

    # 2. Quoted phrase
    if len(words) > 1:
        add(f'"{q_clean}"', "quoted")

    # 3. Known darknet domain synonym mappings
    synonym_map = {
        "card": ["cc dumps", "cvv", "track2", "credit card dumps"],
        "cards": ["cc dumps", "cvv", "track2", "credit card dumps"],
        "credit": ["carding", "bank logs", "fullz"],
        "drug": ["vendor", "escrow", "stealth delivery"],
        "drugs": ["vendor", "escrow", "stealth delivery"],
        "hack": ["database leak", "exploit", "stealer logs"],
        "arms": ["weapons", "firearms", "glock"],
        "malware": ["botnet", "loader", "stealer", "c2"],
        "passport": ["fake id", "counterfeit document", "novelty id"],
    }

    # Location tokens
    location_tokens = {"mumbai", "delhi", "india", "russia", "usa", "uk", "china", "germany"}
    found_locations = [w for w in words if w.lower() in location_tokens]
    has_card_context = any(w.lower() in {"card", "cards", "cc", "cvv", "credit", "dumps"} for w in words)

    for loc in found_locations:
        if has_card_context:
            add(f'"{loc}" cards', "location")
        add(f"{loc} darknet market", "location")
        add(f'"{loc}" {q_clean}', "location")

    for w in words:
        w_lower = w.lower()
        if w_lower in synonym_map:
            for syn in synonym_map[w_lower][:2]:
                combined = f"{syn} {q_clean}" if not syn in q_clean.lower() else syn
                add(combined, "synonym")
                add(f"{syn} darknet escrow", "domain_terminology")

    # General domain terminology fallback
    if len(results) < max_queries:
        add(f"{q_clean} onion escrow", "domain_terminology")
    if len(results) < max_queries:
        add(f"{q_clean} marketplace vendor", "domain_terminology")

    return results[:max_queries]


def _call_opencode_fanout(
    query: str,
    max_queries: int = MAX_FANOUT_QUERIES,
    session_id: Optional[str] = None,
    workspace: Optional[Path] = None,
) -> Optional[List[PlannedQuery]]:
    """Calls local OpenCode daemon to generate intelligent NTRO dark web search terms."""
    from jane.ai.opencode_bridge import _fanout_instruction, send_session_prompt, create_investigation_session, wait_for_opencode_file

    if not workspace:
        return None

    target_file = workspace / "queries" / "fanout.json"
    prompt = _fanout_instruction(workspace, query, max_queries)

    try:
        if not session_id:
            session_id = create_investigation_session(workspace)
        if not session_id:
            return None

        # Ensure no stale output file exists before prompt
        if target_file.exists():
            try:
                target_file.unlink()
            except Exception:
                pass

        # Dispatch prompt asynchronously so OpenCode can work without HTTP timeouts
        sent = send_session_prompt(session_id, prompt, workspace=workspace)
        if not sent:
            logger.warning("Failed to dispatch fanout prompt to OpenCode.")
            return None

        # Wait until OpenCode completes writing the fanout file (up to 120s)
        logger.info(f"Dispatched fanout prompt to OpenCode session {session_id}; waiting for completion...")
        data = wait_for_opencode_file(target_file, session_id=session_id, timeout_seconds=120, poll_interval=1.5)
        if data and isinstance(data, dict):
            items = data.get("queries", [])
            results: List[PlannedQuery] = []
            for it in items:
                if isinstance(it, dict) and "text" in it:
                    results.append(PlannedQuery(
                        text=str(it["text"]).strip(),
                        purpose=str(it.get("purpose", "synonym")).strip(),
                    ))
            if results:
                logger.info(f"OpenCode generated {len(results)} fanout queries successfully.")
                return results[:max_queries]
    except Exception as exc:
        logger.warning(f"OpenCode fanout generation failed: {exc}; using deterministic fallback.")
    return None


def plan_queries(
    query: str,
    max_queries: int = MAX_FANOUT_QUERIES,
    use_llm: bool = True,
    session_id: Optional[str] = None,
    workspace: Optional[Path] = None,
) -> QueryPlan:
    """Generates a bounded query plan (exact + variants)."""
    q = query.strip()
    if not q:
        return QueryPlan(original_query="", queries=[])

    queries: Optional[List[PlannedQuery]] = None
    if use_llm:
        queries = _call_opencode_fanout(q, max_queries=max_queries, session_id=session_id, workspace=workspace)

    generated_by_opencode = bool(queries)
    if not queries:
        queries = _deterministic_fanout(q, max_queries=max_queries)

    source = "opencode" if generated_by_opencode else "deterministic_fallback"
    return QueryPlan(original_query=q, queries=queries, generation_source=source)
