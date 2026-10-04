"""
Jane Collector — Target Ranker & Deduplicator
Aggregates SearchHit objects from multiple queries and providers,
deduplicates by canonical v3 onion address, and applies multi-factor ranking.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Dict, List, Optional
import urllib.parse

from jane.collector.providers import SearchHit

V3_HOST_REGEX = re.compile(r"^[a-z2-7]{56}\.onion$", re.IGNORECASE)


@dataclass
class RankedTarget:
    onion: str
    url: str
    score: float
    found_by: List[str]
    matching_queries: List[str]
    sample_title: str
    sample_snippet: str
    status: str = "queued"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _canonical_onion(url: str) -> Optional[str]:
    u = url.strip()
    if not u.startswith(("http://", "https://")):
        u = f"http://{u}"
    try:
        host = (urllib.parse.urlparse(u).hostname or "").lower()
        if V3_HOST_REGEX.fullmatch(host):
            return host
    except Exception:
        pass
    return None


def rank_targets(
    hits: List[SearchHit],
    total_providers_active: int = 1,
    max_targets: int = 20,
) -> List[RankedTarget]:
    """
    Ranks dark web onion targets based on:
      Score = 0.30 * provider_agreement
            + 0.20 * query_relevance
            + 0.15 * snippet_match
            + 0.15 * url_stability
            + 0.10 * verified_availability
            + 0.10 * source_diversity
    """
    if not hits:
        return []

    # Group hits by canonical onion host
    by_onion: Dict[str, List[SearchHit]] = {}
    for h in hits:
        host = _canonical_onion(h.url)
        if not host:
            continue
        by_onion.setdefault(host, []).append(h)

    ranked: List[RankedTarget] = []

    for host, host_hits in by_onion.items():
        found_by = sorted(list({h.provider for h in host_hits}))
        matching_queries = sorted(list({h.query for h in host_hits}))

        # 1. Provider agreement (0 to 1.0)
        provider_count = len(found_by)
        denom = max(1, total_providers_active)
        s_agreement = min(1.0, provider_count / denom)

        # 2. Query relevance (how many fanout queries matched this onion)
        s_query_relevance = min(1.0, len(matching_queries) / 3.0)

        # 3. Snippet match (relevance score based on text presence)
        snippets = " ".join([h.snippet or "" for h in host_hits])
        titles = " ".join([h.title or "" for h in host_hits])
        text_corp = (snippets + " " + titles).lower()

        keywords = ["market", "escrow", "vendor", "dump", "card", "shop", "service", "leak"]
        matches = sum(1 for kw in keywords if kw in text_corp)
        s_snippet = min(1.0, matches / 4.0)

        # 4. URL stability (clean v3 root vs obscure paths)
        s_stability = 0.85

        # 5. Verified availability
        s_availability = 0.70  # Baseline before active probe

        # 6. Source diversity (presence across clearnet proxy vs direct onion indexes)
        s_diversity = 0.90 if len(found_by) > 1 else 0.50

        # Composite score
        score = (
            0.30 * s_agreement
            + 0.20 * s_query_relevance
            + 0.15 * s_snippet
            + 0.15 * s_stability
            + 0.10 * s_availability
            + 0.10 * s_diversity
        )
        score = round(score, 3)

        sample_title = next((h.title for h in host_hits if h.title), f"Target: {host}")
        sample_snippet = next((h.snippet for h in host_hits if h.snippet), "")

        ranked.append(RankedTarget(
            onion=host,
            url=f"http://{host}",
            score=score,
            found_by=found_by,
            matching_queries=matching_queries,
            sample_title=sample_title,
            sample_snippet=sample_snippet,
            status="queued",
        ))

    # Sort descending by score
    ranked.sort(key=lambda t: t.score, reverse=True)
    return ranked[:max_targets]
