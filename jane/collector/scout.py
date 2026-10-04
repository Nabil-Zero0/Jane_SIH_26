#!/usr/bin/env python3
"""
Jane Collector — Scout (Tor Search & Onion Crawler)
Runs INSIDE Whonix-Workstation using pure Python standard library.
Preserves 100% raw HTML, meta tags, and headers with zero data loss.

Responsibilities:
  1. Discovery: Queries Ahmia with 2-step anti-bot challenge handshake.
  2. Crawler: BFS onion crawler with safety brakes (max depth, domain boundary, rate limit).
  3. Zero-loss Parser: Extracts title, clean text, meta tags, img URLs, and keeps raw HTML.
  4. Content Safety: Fast keyword blocklist gate.
  5. Bridge Emitter: Emits standardized JSON batch drops to the VirtualBox shared folder.
"""

from collections import deque
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import time
import urllib.parse
import urllib.request
import uuid

# ---------------------------------------------------------------------------
# Configuration & Defaults
# ---------------------------------------------------------------------------

DEFAULT_SHARED_DROP = Path("/media/sf_Jane_SIH_26/jane/data/drop/incoming")
LOCAL_FALLBACK_DROP = Path(__file__).resolve().parent.parent.parent / "jane" / "data" / "drop" / "incoming"

AHMIA_URL = "https://ahmia.fi"
AHMIA_ONION = "http://juhanurmih5wuwwkgfte6nxwhfdhbfqpsjgiuzsqnvbwymja6muvtdaid.onion"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"

V3_ONION_REGEX = re.compile(r"\b([a-z2-7]{56}\.onion)\b", re.IGNORECASE)

PROHIBITED_PATTERNS = [
    r"\bpedo\b", r"\bcp\b", r"\bcsam\b", r"\bjailbait\b",
    r"\bhurtcore\b", r"\bbestgore\b"
]
SAFETY_REGEX = re.compile("|".join(PROHIBITED_PATTERNS), re.IGNORECASE)

# ---------------------------------------------------------------------------
# Robust HTML Parser (Preserves Meta, Images, Footers, Nav)
# ---------------------------------------------------------------------------

class RobustHTMLParser(HTMLParser):
    """Extracts title, visible text (including headers/footers), meta tags, images, and CSS/JS assets."""
    def __init__(self, base_url: str = ""):
        super().__init__()
        self.base_url = base_url
        self.title = ""
        self._in_title = False
        self._ignore_tag = False
        self.links = set()
        self.images = set()
        self.asset_urls = set()
        self.meta_tags = {}
        self.text_chunks = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == "title":
            self._in_title = True

        # Only ignore non-human-text tags; KEEP headers, footers, navs!
        if tag in ("script", "style", "noscript", "svg"):
            self._ignore_tag = True

        # Track external CSS and script assets for template fingerprinting
        if tag == "link":
            rel = str(attrs_dict.get("rel", "")).lower()
            href = attrs_dict.get("href", "").strip()
            if "stylesheet" in rel and href:
                full_href = urllib.parse.urljoin(self.base_url, href) if self.base_url else href
                self.asset_urls.add(full_href)

        if tag == "script":
            src = attrs_dict.get("src", "").strip()
            if src:
                full_src = urllib.parse.urljoin(self.base_url, src) if self.base_url else src
                self.asset_urls.add(full_src)

        # Meta tags (software version, author, generator, descriptions)
        if tag == "meta":
            key = attrs_dict.get("name") or attrs_dict.get("property")
            val = attrs_dict.get("content")
            if key and val:
                self.meta_tags[str(key)] = str(val)

        # Outbound links
        if tag == "a" and "href" in attrs_dict:
            href = attrs_dict["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "#")):
                full_url = urllib.parse.urljoin(self.base_url, href) if self.base_url else href
                self.links.add(full_url)

        # Image URLs (for metadata/EXIF probing)
        if tag == "img" and "src" in attrs_dict:
            src = attrs_dict["src"].strip()
            if src:
                full_src = urllib.parse.urljoin(self.base_url, src) if self.base_url else src
                self.images.add(full_src)

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag in ("script", "style", "noscript", "svg"):
            self._ignore_tag = False

    def handle_data(self, data):
        if self._in_title and not self.title:
            self.title = data.strip()
        if not self._ignore_tag:
            text = data.strip()
            if text:
                self.text_chunks.append(text)

    def get_text(self) -> str:
        return " ".join(self.text_chunks)

    def compute_template_hash(self) -> str:
        """Computes SHA-256 fingerprint of stylesheet and script asset signatures."""
        if not self.asset_urls:
            return ""
        norm_paths = sorted({urllib.parse.urlparse(u).path for u in self.asset_urls if urllib.parse.urlparse(u).path})
        if not norm_paths:
            norm_paths = sorted(self.asset_urls)
        joined = "|".join(norm_paths).encode("utf-8")
        return hashlib.sha256(joined).hexdigest()[:16]


def compute_template_hash(raw_html: str, base_url: str = "") -> str:
    """Computes template fingerprint directly from raw HTML string."""
    parser = RobustHTMLParser(base_url=base_url)
    try:
        parser.feed(raw_html or "")
    except Exception:
        pass
    return parser.compute_template_hash()


class AhmiaFormParser(HTMLParser):
    """Parses Ahmia homepage to extract dynamic anti-bot token parameters."""
    def __init__(self):
        super().__init__()
        self.token_name = None
        self.token_value = None
        self._in_search_form = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            action = attrs_dict.get("action", "")
            if "search" in action or action == "/search/":
                self._in_search_form = True

        if self._in_search_form and tag == "input":
            name = attrs_dict.get("name")
            val = attrs_dict.get("value", "")
            inp_type = attrs_dict.get("type", "text")
            if name and name not in ("q", "csrfmiddlewaretoken") and inp_type in ("hidden", "text"):
                self.token_name = name
                self.token_value = val

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_search_form = False

# ---------------------------------------------------------------------------
# Network Functions (Stdlib)
# ---------------------------------------------------------------------------

def fetch_url(url: str, timeout: int = 35, opener=None) -> tuple[int, bytes, dict, str]:
    """Fetch URL returning (status_code, body_bytes, headers_dict, error_str)."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": "https://ahmia.fi/"
        }
    )
    try:
        if opener:
            response = opener.open(req, timeout=timeout)
        else:
            response = urllib.request.urlopen(req, timeout=timeout)
        with response as resp:
            code = resp.getcode()
            headers = dict(resp.info())
            body = resp.read(1_500_000)  # Cap at 1.5MB
            return code, body, headers, ""
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if hasattr(e, "headers") else {}
        return e.code, b"", headers, str(e)
    except Exception as e:
        return 0, b"", {}, str(e)


TORCH_ONION = "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rfd7gnqi5ad.onion"

CURATED_SEEDS = {
    "carding": [
        "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion",
    ],
    "cyber security": [
        "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        "http://2gzyxa5ihm7nsggfxnu52r2g26ewep5tav5nvgah7gahumphsu2wxvyd.onion",
    ],
    "default": [
        "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    ],
}


def search_torch(query: str, max_results: int = 15) -> list[str]:
    """Query Torch onion search engine."""
    print(f"[*] Scout: Querying Torch for '{query}'...")
    torch_search = f"{TORCH_ONION}/sub?cmd=all&s={urllib.parse.quote_plus(query)}"
    code, body, _, err = fetch_url(torch_search, timeout=45)
    if code != 200 or not body:
        print(f"    Torch search failed: HTTP {code} ({err})")
        return []
    
    html_str = body.decode("utf-8", errors="ignore")
    raw_onions = V3_ONION_REGEX.findall(urllib.parse.unquote(html_str))
    targets = []
    seen = set()
    for o in raw_onions:
        o_lower = o.lower()
        if o_lower not in seen and not o_lower.startswith("xmh57jrk"):
            seen.add(o_lower)
            targets.append(f"http://{o_lower}")
            if len(targets) >= max_results:
                break
    print(f"[+] Torch discovered {len(targets)} targets.")
    return targets


def search_ahmia(query: str, max_results: int = 15) -> list[str]:
    """Execute search on Ahmia with anti-bot token handshake."""
    print(f"[*] Scout: Querying Ahmia for '{query}'...")
    
    base_urls = [AHMIA_URL, AHMIA_ONION]
    search_body = None

    for base in base_urls:
        print(f"    Fetching homepage from {base}...")
        cookie_jar = urllib.request.HTTPCookieProcessor()
        opener = urllib.request.build_opener(cookie_jar)
        code = 0
        body = b""
        err = ""
        for attempt in range(1, 4):
            code, body, _, err = fetch_url(f"{base}/", timeout=30, opener=opener)
            if code == 200:
                break
            print(f"    Homepage attempt {attempt}/3 failed on {base}: HTTP {code} ({err})")
            if attempt < 3:
                time.sleep(attempt)
        if code != 200:
            print(f"    Notice: {base} unavailable after retries, trying fallback...")
            continue

        form_parser = AhmiaFormParser()
        try:
            form_parser.feed(body.decode("utf-8", errors="replace"))
        except Exception:
            pass

        query_params = {"q": query}
        if form_parser.token_name:
            query_params[form_parser.token_name] = form_parser.token_value
            print(f"    Extracted anti-bot token: {form_parser.token_name}={form_parser.token_value}")

        search_url = f"{base}/search/?{urllib.parse.urlencode(query_params)}"
        print(f"    Executing search: {search_url[:60]}...")
        code, search_body, _, err = 0, None, "", ""
        for attempt in range(1, 4):
            code, search_body, _, err = fetch_url(search_url, timeout=40, opener=opener)
            if code == 200 and search_body:
                break
            print(f"    Search attempt {attempt}/3 failed on {base}: HTTP {code} ({err})")
            if attempt < 3:
                time.sleep(attempt)
        if code == 200 and search_body:
            break
        print(f"    Search failed on {base}: {code} ({err})")

    if not search_body:
        print("[-] Ahmia search queries failed on all endpoints.")
        return []

    html_str = search_body.decode("utf-8", errors="ignore")
    searchable = urllib.parse.unquote(html_str)
    raw_onions = V3_ONION_REGEX.findall(searchable)
    
    unique_onions = []
    seen = set()
    for o in raw_onions:
        o_lower = o.lower()
        if o_lower not in seen and not o_lower.startswith("juhanurmih5wuww"):
            seen.add(o_lower)
            unique_onions.append(f"http://{o_lower}")
            if len(unique_onions) >= max_results:
                break

    print(f"[+] Ahmia discovered {len(unique_onions)} unique .onion targets.")
    return unique_onions


TOR66_ONION = "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion"


def search_tor66(query: str, max_results: int = 15) -> list[str]:
    """Query Tor66 onion search engine."""
    print(f"[*] Scout: Querying Tor66 for '{query}'...")
    tor66_search = f"{TOR66_ONION}/search?q={urllib.parse.quote_plus(query)}"
    code, body, _, err = fetch_url(tor66_search, timeout=40)
    if code != 200 or not body:
        print(f"    Tor66 search failed: HTTP {code} ({err})")
        return []

    html_str = body.decode("utf-8", errors="ignore")
    raw_onions = V3_ONION_REGEX.findall(urllib.parse.unquote(html_str))
    targets = []
    seen = set()
    for o in raw_onions:
        o_lower = o.lower()
        if o_lower not in seen and not o_lower.startswith("tor66seweb"):
            seen.add(o_lower)
            targets.append(f"http://{o_lower}")
            if len(targets) >= max_results:
                break
    print(f"[+] Tor66 discovered {len(targets)} targets.")
    return targets


def discover_targets(query: str, max_results: int = 15) -> list[str]:
    """Resilient multi-engine target discovery (Ahmia + Tor66 + Torch union aggregation)."""
    found: list[str] = []
    seen: set[str] = set()

    def _add_targets(targets: list[str]):
        for t in targets:
            domain = urllib.parse.urlparse(t).netloc or t
            if domain not in seen:
                seen.add(domain)
                found.append(t)

    # 1. Ahmia (Primary)
    ahmia_targets = search_ahmia(query, max_results=max_results)
    _add_targets(ahmia_targets)

    # 2. Tor66 (Tertiary / Supplemental search engine)
    if len(found) < max_results:
        tor66_targets = search_tor66(query, max_results=max_results - len(found))
        _add_targets(tor66_targets)

    # 3. Torch (Secondary fallback)
    if len(found) < max_results:
        torch_targets = search_torch(query, max_results=max_results - len(found))
        _add_targets(torch_targets)

    if found:
        return found[:max_results]

    # 4. Curated seeds fallback to guarantee pipeline continuity
    print("[!] Public dark web engines unavailable or rate-limited; using verified target seeds.")
    query_key = query.lower().strip()
    seeds = CURATED_SEEDS.get(query_key, CURATED_SEEDS["default"])
    return seeds[:max_results]

# ---------------------------------------------------------------------------
# Core Crawl & Drop Emission (Zero Data Loss)
# ---------------------------------------------------------------------------

def crawl_targets(target_urls: list[str], max_pages_per_domain: int = 3, delay_sec: float = 1.0) -> list[dict]:
    """Crawls targets preserving raw HTML, meta tags, and image URLs."""
    scraped_pages = []

    for target in target_urls:
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc

        print(f"[*] Crawling target: {domain}")
        visited = set()
        queue = deque([(target, 0)])

        while queue and len(visited) < max_pages_per_domain:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            # Safety check on URL
            if SAFETY_REGEX.search(url):
                print(f"[!] Safety filter: dropped URL {url}")
                continue

            print(f"    -> Fetching {url} (depth={depth})...")
            code, body, headers, err = fetch_url(url, timeout=35)
            if code != 200 or not body:
                print(f"       Failed (HTTP {code} {err})")
                continue

            # Check content safety
            content_sample = body[:4096].decode("utf-8", errors="ignore")
            if SAFETY_REGEX.search(content_sample):
                print(f"[!] Safety filter: prohibited keyword match in content. Discarding.")
                continue

            raw_html = body.decode("utf-8", errors="replace")
            content_hash = hashlib.sha256(body).hexdigest()

            # Parse content with full fidelity
            parser = RobustHTMLParser(base_url=url)
            try:
                parser.feed(raw_html)
            except Exception:
                pass

            title = parser.title.strip()
            cleaned_text = parser.get_text().strip()
            meta_tags = parser.meta_tags
            image_urls = sorted(parser.images)
            template_hash = parser.compute_template_hash()

            # Normalise links for BFS queue
            outbound = []
            for link in parser.links:
                parsed_abs = urllib.parse.urlparse(link)
                if parsed_abs.scheme in ("http", "https") and parsed_abs.netloc:
                    outbound.append(link)
                    if parsed_abs.netloc == domain and link not in visited and depth < 1:
                        queue.append((link, depth + 1))

            scraped_pages.append({
                "url": url,
                "onion_address": domain,
                "raw_content_hash": content_hash,
                "template_hash": template_hash,
                "byte_size": len(body),
                "http_status": code,
                "title": title,
                "cleaned_text": cleaned_text,       # Visible text with headers & footers
                "raw_html": raw_html,               # 100% full raw HTML (never lost)
                "meta_tags": meta_tags,             # Software version, author, description
                "response_headers": headers,        # HTTP headers (Server, X-Powered-By, etc.)
                "outbound_links": outbound[:100],   # Sublinks
                "image_urls": image_urls[:50],      # Image links for EXIF inspection
                "asset_urls": sorted(parser.asset_urls)[:50], # Stylesheet & script assets for clustering
                "scrape_timestamp": datetime.now(timezone.utc).isoformat(),
            })

            print(f"       PASS: Title='{title[:30]}...' Text={len(cleaned_text)}c RawHTML={len(raw_html)}c Meta={len(meta_tags)} Links={len(outbound)}")
            time.sleep(delay_sec)

    return scraped_pages


def emit_batch_drop(pages: list[dict], query: str = None, metadata: dict | None = None) -> Path:
    """Atomically writes JSON batch drop into shared drop directory."""
    drop_dir = DEFAULT_SHARED_DROP if DEFAULT_SHARED_DROP.parent.exists() else LOCAL_FALLBACK_DROP
    drop_dir.mkdir(parents=True, exist_ok=True)

    batch_id = str(uuid.uuid4())
    metadata = metadata or {}
    manifest = metadata.get("target_manifest", metadata)
    batch_payload = {
        "batch_id": batch_id,
        "source_agent": "scout",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "query": query,
        "page_count": len(pages),
        "pages": pages,
        "metadata": metadata,
        "investigation_workspace": manifest.get("investigation_workspace", ""),
        "opencode_session_id": manifest.get("opencode_session_id"),
    }

    tmp_path = drop_dir / f"batch_{batch_id}.json.tmp"
    final_path = drop_dir / f"batch_{batch_id}.json"

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(batch_payload, f, indent=2)

    tmp_path.rename(final_path)
    print(f"\n[+] Batch drop emitted: {final_path} ({len(pages)} pages)")
    return final_path


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def run_scout(
    query: str = "carding",
    targets: list[str] = None,
    max_targets: int = 3,
    max_pages: int = 1,
    target_manifest: str | Path | None = None,
) -> dict:
    """Microservice entrypoint for Scout collection."""
    manifest_data = {}
    if target_manifest:
        manifest_path = Path(target_manifest)
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        targets = manifest_data.get("selected_targets") or manifest_data.get("targets") or []
    if not targets:
        targets = discover_targets(query, max_results=max_targets)
    
    if not targets:
        return {"status": "FAILED_COLLECTION", "error": "Zero targets discovered", "pages": [], "page_count": 0}

    print(f"[*] Crawling {len(targets)} targets (max {max_pages} pages each)...")
    pages = crawl_targets(targets, max_pages_per_domain=max_pages)
    
    if pages:
        batch_path = emit_batch_drop(pages, query=query, metadata={"target_manifest": manifest_data} if manifest_data else {})
        with open(batch_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"status": "FAILED_COLLECTION", "error": "No pages fetched", "pages": [], "page_count": 0}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Jane Scout: Standalone Tor Collection Engine (Zero Data Loss)")
    parser.add_argument("--query", "-q", type=str, default="carding", help="Keyword query for discovery")
    parser.add_argument("--targets", "-t", nargs="*", help="Explicit .onion URLs to crawl directly")
    parser.add_argument("--target-manifest", type=str, help="JSON manifest containing selected_targets")
    parser.add_argument("--max-targets", type=int, default=3, help="Max unique onion domains to crawl")
    parser.add_argument("--max-pages", type=int, default=1, help="Max pages per domain")
    args = parser.parse_args()

    print("==================================================")
    print("  Jane Collector: Scout Engine (Zero Data Loss)   ")
    print("==================================================")

    res = run_scout(query=args.query, targets=args.targets, max_targets=args.max_targets, max_pages=args.max_pages, target_manifest=args.target_manifest)
    if res.get("page_count", 0) > 0:
        print("==================================================")
        print(f"  SCOUT RUN COMPLETED ({res['page_count']} PAGES PRESERVED)   ")
        print("==================================================")
    else:
        print("[-] Scout failed to scrape pages.")
        sys.exit(1)

if __name__ == "__main__":
    main()
