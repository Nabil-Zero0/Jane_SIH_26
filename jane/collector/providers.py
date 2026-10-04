"""
Jane Collector — Unified Search Provider Layer
Provides a common SearchProvider protocol for Ahmia, Torch, Tor66, and Curated Seeds.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Protocol
import urllib.parse

from jane.collector.scout import (
    search_ahmia,
    search_torch,
    CURATED_SEEDS,
    V3_ONION_REGEX,
    fetch_url,
)

logger = logging.getLogger("jane.collector.providers")


@dataclass
class SearchHit:
    url: str
    title: Optional[str]
    snippet: Optional[str]
    provider: str
    query: str
    discovered_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "title": self.title,
            "snippet": self.snippet,
            "provider": self.provider,
            "query": self.query,
            "discovered_at": self.discovered_at,
        }


class SearchProvider(Protocol):
    name: str

    def search(self, query: str, limit: int = 30) -> List[SearchHit]:
        ...


class AhmiaProvider:
    name: str = "ahmia"

    def search(self, query: str, limit: int = 30) -> List[SearchHit]:
        try:
            urls = search_ahmia(query, max_results=limit)
            now = datetime.now(timezone.utc).isoformat()
            return [
                SearchHit(
                    url=u,
                    title=f"Ahmia Lead: {u}",
                    snippet=f"Discovered via Ahmia for '{query}'",
                    provider=self.name,
                    query=query,
                    discovered_at=now,
                )
                for u in urls
            ]
        except Exception as exc:
            logger.warning(f"AhmiaProvider search error: {exc}")
            return []


class TorchProvider:
    name: str = "torch"

    def search(self, query: str, limit: int = 30) -> List[SearchHit]:
        try:
            urls = search_torch(query, max_results=limit)
            now = datetime.now(timezone.utc).isoformat()
            return [
                SearchHit(
                    url=u,
                    title=f"Torch Lead: {u}",
                    snippet=f"Discovered via Torch for '{query}'",
                    provider=self.name,
                    query=query,
                    discovered_at=now,
                )
                for u in urls
            ]
        except Exception as exc:
            logger.warning(f"TorchProvider search error: {exc}")
            return []


class Tor66Provider:
    name: str = "tor66"
    TOR66_ONION = "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion"

    def search(self, query: str, limit: int = 30) -> List[SearchHit]:
        now = datetime.now(timezone.utc).isoformat()
        try:
            url = f"{self.TOR66_ONION}/search?q={urllib.parse.quote_plus(query)}"
            code, body, _, err = fetch_url(url, timeout=40)
            if code != 200 or not body:
                return []
            html_str = body.decode("utf-8", errors="ignore")
            onions = V3_ONION_REGEX.findall(urllib.parse.unquote(html_str))
            hits: List[SearchHit] = []
            seen: set[str] = set()
            for o in onions:
                o_low = o.lower()
                if o_low not in seen and not o_low.startswith("tor66seweb"):
                    seen.add(o_low)
                    hits.append(SearchHit(
                        url=f"http://{o_low}",
                        title=f"Tor66 Lead: {o_low}",
                        snippet=f"Discovered via Tor66 for '{query}'",
                        provider=self.name,
                        query=query,
                        discovered_at=now,
                    ))
                    if len(hits) >= limit:
                        break
            return hits
        except Exception as exc:
            logger.warning(f"Tor66Provider search error: {exc}")
            return []


class CuratedSeedsProvider:
    name: str = "seeds"

    def search(self, query: str, limit: int = 30) -> List[SearchHit]:
        now = datetime.now(timezone.utc).isoformat()
        q_low = query.lower()
        seeds: List[str] = []
        for cat, urls in CURATED_SEEDS.items():
            if cat != "default" and (cat in q_low or any(w in q_low for w in cat.split())):
                seeds.extend(urls)
        if not seeds:
            seeds = CURATED_SEEDS.get("default", [])

        return [
            SearchHit(
                url=u,
                title=f"Curated Seed: {u}",
                snippet=f"Curated reference seed matching '{query}'",
                provider=self.name,
                query=query,
                discovered_at=now,
            )
            for u in seeds[:limit]
        ]


PROVIDER_REGISTRY: Dict[str, SearchProvider] = {
    "ahmia": AhmiaProvider(),
    "torch": TorchProvider(),
    "tor66": Tor66Provider(),
    "seeds": CuratedSeedsProvider(),
}


def get_providers(names: Optional[List[str]] = None) -> List[SearchProvider]:
    """Returns requested search providers (defaults to ahmia + seeds)."""
    if not names:
        names = ["ahmia", "seeds"]
    selected: List[SearchProvider] = []
    for n in names:
        p = PROVIDER_REGISTRY.get(n.lower().strip())
        if p and p not in selected:
            selected.append(p)
    if not selected:
        selected = [PROVIDER_REGISTRY["ahmia"]]
    return selected


def safe_search(provider: SearchProvider, query: str, limit: int = 30) -> List[SearchHit]:
    """Isolates search failures so one failing engine never crashes the search run."""
    try:
        logger.info(f"[*] Running provider '{provider.name}' for query: '{query}'")
        return provider.search(query, limit=limit)
    except Exception as exc:
        logger.warning(f"Safe search failed on provider '{provider.name}': {exc}")
        return []
