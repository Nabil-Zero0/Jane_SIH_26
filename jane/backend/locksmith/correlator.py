"""
Jane Backend — Locksmith Clearnet Correlator
Runs on Windows Host.
Reads locksmith probe drops from data/drop/incoming/ (or processed),
extracts favicon mmh3 hashes, server banners, and leaked IPs,
enriches via Shodan InternetDB (free API), and links clearnet infrastructure
to the .onion source in data/jane.db.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("jane.backend.locksmith")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
import sqlite3

DEFAULT_DB_PATH = REPO_ROOT / "data" / "jane.db"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io"


def query_shodan_internetdb(ip: str) -> Optional[Dict[str, Any]]:
    """Queries free Shodan InternetDB API for open ports, CVEs, and hostnames."""
    url = f"{SHODAN_INTERNETDB_URL}/{ip}"
    req = urllib.request.Request(url, headers={"User-Agent": "Jane-Threat-OSINT/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as he:
        if he.code == 404:
            logger.info(f"Shodan InternetDB: No records for {ip}")
        else:
            logger.warning(f"Shodan InternetDB HTTP {he.code} for {ip}")
    except Exception as e:
        logger.warning(f"Shodan InternetDB query failed for {ip}: {e}")
    return None


def ingest_locksmith_drop(drop_file: Path) -> Dict[str, Any]:
    """Processes a locksmith probe JSON and updates jane.db."""
    logger.info(f"Ingesting Locksmith drop: {drop_file.name}")
    with open(drop_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    conn = sqlite3.connect(DEFAULT_DB_PATH)
    cursor = conn.cursor()

    probes = data.get("results", [])
    correlated_findings = []

    for probe in probes:
        onion = probe.get("onion_address")
        server_banner = probe.get("server_banner")
        favicon = probe.get("favicon") or {}
        mmh3_hash = favicon.get("mmh3_hash")
        leaked_ips = probe.get("leaked_ips") or []

        logger.info(f"Analyzing probe for {onion}:")
        if server_banner:
            logger.info(f"  Server Banner: {server_banner}")
        if mmh3_hash:
            logger.info(f"  Favicon mmh3: {mmh3_hash} (Search: http.favicon.hash:{mmh3_hash})")

        enriched_ips = []
        for ip in leaked_ips:
            logger.info(f"  Enriching leaked IP {ip} via Shodan InternetDB...")
            shodan_data = query_shodan_internetdb(ip)
            enriched_ips.append({
                "ip": ip,
                "shodan": shodan_data,
            })

        finding = {
            "onion_address": onion,
            "server_banner": server_banner,
            "mmh3_hash": mmh3_hash,
            "shodan_query": favicon.get("shodan_query"),
            "leaked_ips": enriched_ips,
        }
        correlated_findings.append(finding)

        # Persist into jane.db entities table
        now = datetime.now(timezone.utc).isoformat()
        page_row = cursor.execute("SELECT id FROM pages WHERE url LIKE ?", (f"%{onion}%",)).fetchone()
        page_id = page_row[0] if page_row else None

        if mmh3_hash is not None:
            val_str = str(mmh3_hash)
            cursor.execute("""
                INSERT OR IGNORE INTO entities 
                (id, entity_type, value, canonical_value, confidence, context_snippet, extraction_method, first_seen, last_seen, created_at, page_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                os.urandom(16).hex(),
                "FAVICON_MMH3",
                val_str,
                val_str,
                1.0,
                f"Shodan search: http.favicon.hash:{val_str} | Onion: {onion}",
                "locksmith",
                now,
                now,
                now,
                page_id,
            ))

        if server_banner:
            cursor.execute("""
                INSERT OR IGNORE INTO entities 
                (id, entity_type, value, canonical_value, confidence, context_snippet, extraction_method, first_seen, last_seen, created_at, page_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                os.urandom(16).hex(),
                "SERVER_BANNER",
                server_banner,
                server_banner.lower(),
                1.0,
                f"HTTP Server header: {server_banner} | Onion: {onion}",
                "locksmith",
                now,
                now,
                now,
                page_id,
            ))

    conn.commit()
    conn.close()

    # Move processed file to archive
    processed_dir = REPO_ROOT / "data" / "drop" / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)
    dest_path = processed_dir / drop_file.name
    import shutil
    shutil.move(str(drop_file), str(dest_path))
    logger.info(f"Archived locksmith drop to {dest_path.name}")

    return {
        "batch_id": data.get("batch_id"),
        "findings": correlated_findings,
    }


def run_locksmith(batch_data: Dict[str, Any]) -> Dict[str, Any]:
    """Microservice entrypoint: Extracts infrastructure indicators from Scout batch pages."""
    pages = batch_data.get("pages", [])
    findings = []

    for page in pages:
        onion = page.get("onion_address", "")
        headers = page.get("response_headers", {}) or {}
        # Case insensitive header lookup
        header_map = {k.lower(): v for k, v in headers.items()}
        server_banner = header_map.get("server")
        etag = header_map.get("etag")
        
        # Check for leaked IPs in text/HTML
        text_corpus = f"{page.get('title', '')}\n{page.get('cleaned_text', '')}"
        ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text_corpus)
        leaked_ips = [ip for ip in set(ip_matches) if not ip.startswith(("127.", "10.", "192.168.", "0."))]

        enriched_ips = []
        for ip in leaked_ips[:3]:
            shodan_data = query_shodan_internetdb(ip)
            enriched_ips.append({"ip": ip, "shodan": shodan_data})

        finding = {
            "onion_address": onion,
            "url": page.get("url", ""),
            "server_banner": server_banner,
            "etag": etag,
            "leaked_ips": enriched_ips,
        }
        findings.append(finding)

    return {
        "status": "LOCKSMITH_ANALYZED",
        "batch_id": batch_data.get("batch_id", ""),
        "findings_count": len(findings),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Jane Locksmith Clearnet Correlator")
    parser.add_argument("--batch", "-b", type=str, help="Path to Scout batch JSON file")
    parser.add_argument("--file", type=str, help="Path to a specific locksmith drop JSON")
    args = parser.parse_args()

    if args.batch:
        batch_path = Path(args.batch)
        if not batch_path.exists():
            print(f"Error: {args.batch} not found")
            sys.exit(1)
        with open(batch_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        res = run_locksmith(data)
        print(json.dumps(res, indent=2))
    elif args.file:
        res = ingest_locksmith_drop(Path(args.file))
        print(json.dumps(res, indent=2))
    else:
        incoming = REPO_ROOT / "data" / "drop" / "incoming"
        files = sorted(incoming.glob("locksmith_*.json"))
        if not files:
            logger.info("No pending locksmith drops found in data/drop/incoming/.")
            return
        for f in files:
            res = ingest_locksmith_drop(f)
            print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
