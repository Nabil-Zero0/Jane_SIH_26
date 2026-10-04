"""Whonix-only multi-engine onion discovery using standard library code."""

from __future__ import annotations

from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

ENGINE_NAMES = (
    "Ahmia (Clearnet Proxy)", "DarkSearch (API)", "Ahmia", "OnionLand", "Torgle",
)
ONION_RE = re.compile(r"https?://[a-z2-7]{56}\.onion(?:/[^\s\"'<>]*)?", re.I)
HOST_RE = re.compile(r"^[a-z2-7]{56}\.onion$", re.I)
USER_AGENT = "Jane-Whonix-Collector/1.0"
REQUEST_TIMEOUT = 30
RETRIES = 2


@dataclass(frozen=True)
class DiscoveryResult:
    targets: list[str]
    engines: list[dict[str, Any]]


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href = ""
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href:
            self.links.append((self._href, " ".join(self._text).strip()))
            self._href, self._text = "", []


from jane.collector.engine_catalog import SEARCH_ENGINES


def _load_catalog() -> list[dict[str, str]]:
    return list(SEARCH_ENGINES)


def _canonical_target(url: str) -> str | None:
    match = ONION_RE.search(str(url).strip().lower())
    if not match:
        return None
    host = (urllib.parse.urlparse(match.group(0)).hostname or "").lower()
    return f"http://{host}" if HOST_RE.fullmatch(host) else None


def _fetch(url: str) -> tuple[int, bytes, str]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return response.getcode(), response.read(2_000_000), ""
    except urllib.error.HTTPError as exc:
        return exc.code, b"", str(exc)
    except Exception as exc:
        return 0, b"", str(exc)


def _extract_links(body: bytes, blocked_hosts: set[str]) -> list[dict[str, str]]:
    text = body.decode("utf-8", errors="replace")
    parser = _LinkParser()
    try:
        parser.feed(text)
    except Exception:
        pass
    candidates = parser.links + [(match, "") for match in ONION_RE.findall(text)]
    found: OrderedDict[str, str] = OrderedDict()
    for raw, title in candidates:
        for match in ONION_RE.findall(urllib.parse.unquote(raw)):
            target = _canonical_target(match)
            if target and urllib.parse.urlparse(target).hostname not in blocked_hosts:
                found.setdefault(target, title or target)
    return [{"link": link, "title": title} for link, title in found.items()]


def _query_engine(engine: dict[str, str], query: str, blocked_hosts: set[str]) -> dict[str, Any]:
    url = engine["url"].format(query=urllib.parse.quote_plus(query))
    started = time.monotonic()
    last_error = ""
    for attempt in range(RETRIES + 1):
        code, body, error = _fetch(url)
        if code == 200 and body:
            try:
                if "darksearch.io/api" in url:
                    payload = json.loads(body.decode("utf-8", errors="replace"))
                    links = [{"link": item.get("onion", ""), "title": item.get("title", "")} for item in payload.get("data", [])]
                    links = [item for item in links if _canonical_target(item["link"])]
                else:
                    links = _extract_links(body, blocked_hosts)
            except Exception as exc:
                return {"name": engine["name"], "success": False, "error": f"parse: {exc}", "took_ms": int((time.monotonic() - started) * 1000), "links_found": 0, "links": []}
            return {"name": engine["name"], "success": bool(links), "error": None if links else "no valid onion links", "took_ms": int((time.monotonic() - started) * 1000), "links_found": len(links), "links": links}
        last_error = f"HTTP {code} ({error})"
        if attempt < RETRIES:
            time.sleep(0.5 * (attempt + 1))
    return {"name": engine["name"], "success": False, "error": last_error, "took_ms": int((time.monotonic() - started) * 1000), "links_found": 0, "links": []}


def discover_onions(query: str, max_results: int = 3) -> DiscoveryResult:
    """Query five engines concurrently and return ranked unique onion hosts."""
    catalog = {engine["name"]: engine for engine in _load_catalog()}
    engines = [catalog[name] for name in ENGINE_NAMES if name in catalog]
    if len(engines) != len(ENGINE_NAMES):
        raise RuntimeError("SEARCH_ENGINE_DEPENDENCY_ERROR: selected engine missing from catalog")

    blocked_hosts = {
        (urllib.parse.urlparse(engine["url"]).hostname or "").lower()
        for engine in engines
    }
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=len(engines), thread_name_prefix="jane-search") as pool:
        futures = [pool.submit(_query_engine, engine, query, blocked_hosts) for engine in engines]
        for future in as_completed(futures):
            results.append(future.result())

    priority = {name: len(ENGINE_NAMES) - index for index, name in enumerate(ENGINE_NAMES)}
    ranked: OrderedDict[str, dict[str, Any]] = OrderedDict()
    metadata = []
    for result in sorted(results, key=lambda item: priority.get(item["name"], 0), reverse=True):
        metadata.append({key: result[key] for key in ("name", "success", "error", "took_ms", "links_found")})
        for link in result["links"]:
            target = _canonical_target(link["link"])
            if target:
                item = ranked.setdefault(target, {"sources": [], "priority": priority.get(result["name"], 0)})
                if result["name"] not in item["sources"]:
                    item["sources"].append(result["name"])

    first_seen = {target: index for index, target in enumerate(ranked)}
    ordered = sorted(ranked.items(), key=lambda pair: (-len(pair[1]["sources"]), -pair[1]["priority"], first_seen[pair[0]]))
    return DiscoveryResult([target for target, _ in ordered[:max_results]], metadata)
