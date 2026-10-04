"""
Jane Bridge — Host Ingestion Pipeline
Monitors incoming crawl batches from Whonix shared folder (data/drop/incoming/),
runs VoidAccess-compatible entity extraction across cleaned text & raw HTML,
deduplicates entities globally, and persists intelligence into the local database (SQLite/Postgres).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("jane.bridge.ingest")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

try:
    from jane.db.models import (
        Base,
        Investigation,
        Page,
        Source,
        Entity,
        EntityRelationship,
        RelationshipType,
    )
    from jane.db.queries import upsert_entity_canonical
    from jane.backend.regex_patterns import extract_all
    from jane.backend.normalizer import canonicalize_entity_value
    HAS_VOIDACCESS = True
except Exception as exc:
    logger.error(f"Failed to import core modules: {exc}")
    HAS_VOIDACCESS = False

DEFAULT_DB_PATH = REPO_ROOT / "data" / "jane.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}")

INCOMING_DIR = REPO_ROOT / "data" / "drop" / "incoming"
PROCESSED_DIR = REPO_ROOT / "data" / "drop" / "processed"

# Hub types for co-occurrence edge creation
HUB_TYPES = frozenset({
    "THREAT_ACTOR_HANDLE",
    "RANSOMWARE_GROUP",
    "MALWARE_FAMILY",
    "CVE_NUMBER",
})

IOC_TYPES = frozenset({
    "BITCOIN_ADDRESS",
    "ETHEREUM_ADDRESS",
    "MONERO_ADDRESS",
    "LITECOIN_ADDRESS",
    "EMAIL_ADDRESS",
    "PGP_KEY_BLOCK",
    "ONION_URL",
    "FILE_HASH_SHA256",
    "FILE_HASH_MD5",
    "TELEGRAM_HANDLE",
    "DISCORD_HANDLE",
    "XMPP_JID",
    "TOX_ID",
    "SESSION_ID",
    "IP_ADDRESS",
})


def get_db_session() -> Tuple[Any, sessionmaker]:
    """Initializes database engine and ensures all tables exist."""
    engine = create_engine(DATABASE_URL, echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return engine, session_factory


import difflib

# Format-rigidity calibrated confidence ladder
ENTITY_CONFIDENCE_TABLE: Dict[str, float] = {
    "PGP_KEY_BLOCK": 0.98,
    "MONERO_ADDRESS": 0.98,
    "TOX_ID": 0.98,
    "SESSION_ID": 0.98,
    "BITCOIN_ADDRESS": 0.90,
    "ETHEREUM_ADDRESS": 0.90,
    "LITECOIN_ADDRESS": 0.90,
    "ONION_URL": 0.90,
    "CVE_NUMBER": 0.90,
    "FILE_HASH_SHA256": 0.95,
    "FILE_HASH_MD5": 0.90,
    "TELEGRAM_HANDLE": 0.75,
    "DISCORD_HANDLE": 0.75,
    "EMAIL_ADDRESS": 0.75,
    "WIRE_HANDLE": 0.50,
    "IP_ADDRESS": 0.50,
    "DEFAULT": 0.70,
}


def extract_context_snippet(text: str, match_value: str, window: int = 150) -> str:
    """Extracts a readable context window snapped to sentence boundaries."""
    if not text or not match_value:
        return ""
    pos = text.find(match_value)
    if pos == -1:
        return ""
    start = max(0, pos - window)
    end = min(len(text), pos + len(match_value) + window)

    # Snap backward to nearest period or newline
    if start > 0:
        last_delim = max(text.rfind('.', start, pos), text.rfind('\n', start, pos))
        if last_delim != -1:
            start = last_delim + 1

    # Snap forward to nearest period or newline
    if end < len(text):
        next_p = text.find('.', pos + len(match_value), end)
        next_nl = text.find('\n', pos + len(match_value), end)
        delims = [x for x in (next_p, next_nl) if x != -1]
        if delims:
            end = min(delims) + 1

    snippet = text[start:end].replace("\r", " ").replace("\n", " ").strip()
    return snippet[:300]


def process_page(
    session: Session,
    page_data: Dict[str, Any],
    investigation_id: uuid.UUID,
) -> Tuple[Page, List[Entity], int, int]:
    """
    Ingests a single scraped page, extracts all entities from text and raw HTML,
    deduplicates globally via canonical upsert, and links to the investigation.
    """
    url = page_data.get("url", "").strip()
    if not url:
        raise ValueError("Page record missing URL")

    # 1. Resolve or create Source (.onion domain)
    onion_address = page_data.get("onion_address")
    source = None
    if onion_address:
        source = session.query(Source).filter_by(onion_address=onion_address).first()
        if not source:
            source = Source(
                id=uuid.uuid4(),
                onion_address=onion_address,
                source_type="crawled",
                status="active",
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            session.add(source)
            session.flush()

    # 2. Resolve or create Page
    page = session.query(Page).filter_by(url=url).first()
    cleaned_text = page_data.get("cleaned_text") or ""
    raw_html = page_data.get("raw_html") or ""
    diff_ratio = 1.0

    if not page:
        page = Page(
            id=uuid.uuid4(),
            source_id=source.id if source else None,
            url=url,
            raw_content_hash=page_data.get("raw_content_hash"),
            cleaned_text=cleaned_text[:100000] if cleaned_text else None,
            byte_size=page_data.get("byte_size"),
            scrape_timestamp=datetime.now(timezone.utc),
        )
        session.add(page)
        session.flush()
    else:
        # Change detection using difflib
        if page.cleaned_text and cleaned_text:
            diff_ratio = round(difflib.SequenceMatcher(None, page.cleaned_text, cleaned_text).ratio(), 3)
            if diff_ratio < 0.85 and abs(len(cleaned_text) - len(page.cleaned_text)) > 50:
                logger.info(f"Page content change detected on {url}: similarity={diff_ratio * 100:.1f}%")
        if cleaned_text and (not page.cleaned_text or len(cleaned_text) > len(page.cleaned_text)):
            page.cleaned_text = cleaned_text[:100000]
        session.flush()

    # 3. Extract entities across both cleaned_text and raw_html
    text_matches = extract_all(cleaned_text) if cleaned_text else {}
    html_matches = extract_all(raw_html) if raw_html else {}

    combined: Dict[str, Set[str]] = {}
    for source_dict in (text_matches, html_matches):
        for etype, vals in source_dict.items():
            if etype not in combined:
                combined[etype] = set()
            for v in vals:
                if v and len(v) < 2048:
                    combined[etype].add(v)

    # 4. Upsert entities canonically with format-rigidity confidence
    persisted_entities: List[Entity] = []
    new_count = 0
    merged_count = 0

    if "ONION_URL" in combined and len(combined["ONION_URL"]) > 50:
        combined["ONION_URL"] = set(list(combined["ONION_URL"])[:50])

    for etype, values in combined.items():
        conf = ENTITY_CONFIDENCE_TABLE.get(etype, ENTITY_CONFIDENCE_TABLE["DEFAULT"])
        for val in values:
            val_clean = val.strip()
            if not val_clean:
                continue

            snippet = extract_context_snippet(cleaned_text, val_clean)
            if not snippet:
                snippet = extract_context_snippet(raw_html, val_clean)

            db_entity, created = upsert_entity_canonical(
                session=session,
                investigation_id=investigation_id,
                entity_type=etype,
                entity_value=val_clean,
                confidence=conf,
                source_page_id=page.id,
                context_snippet=snippet,
                extraction_method="regex",
            )
            persisted_entities.append(db_entity)
            if created:
                new_count += 1
            else:
                merged_count += 1

    # 5. Build STIX 2.1 & Darknet Edges
    hubs = [e for e in persisted_entities if e.entity_type in HUB_TYPES]
    iocs = [e for e in persisted_entities if e.entity_type in IOC_TYPES]

    relationships_created = 0
    if hubs and iocs:
        for hub in hubs:
            for ioc in iocs:
                # STIX 2.1 taxonomy mapping
                rel_type = "uses"
                if ioc.entity_type in ("BITCOIN_ADDRESS", "MONERO_ADDRESS", "ETHEREUM_ADDRESS"):
                    rel_type = "uses"
                elif ioc.entity_type in ("TELEGRAM_HANDLE", "WIRE_HANDLE", "EMAIL_ADDRESS", "PGP_KEY_BLOCK"):
                    rel_type = "uses"
                elif ioc.entity_type == "ONION_URL":
                    rel_type = "posted_by"
                elif ioc.entity_type in ("CVE_NUMBER", "FILE_HASH_SHA256"):
                    rel_type = "indicates"

                rel = EntityRelationship(
                    id=uuid.uuid4(),
                    entity_a_id=hub.id,
                    entity_b_id=ioc.id,
                    relationship_type=rel_type,
                    source_page_id=page.id,
                    confidence=conf,
                    investigation_id=investigation_id,
                    first_seen=datetime.now(timezone.utc),
                )
                session.add(rel)
                relationships_created += 1
    elif len(iocs) >= 2 and len(iocs) <= 25:
        for i in range(len(iocs)):
            for j in range(i + 1, min(i + 4, len(iocs))):
                rel = EntityRelationship(
                    id=uuid.uuid4(),
                    entity_a_id=iocs[i].id,
                    entity_b_id=iocs[j].id,
                    relationship_type="related-to",
                    source_page_id=page.id,
                    confidence=0.70,
                    investigation_id=investigation_id,
                    first_seen=datetime.now(timezone.utc),
                )
                session.add(rel)
                relationships_created += 1

    return page, persisted_entities, new_count, merged_count


def ingest_batch_file(filepath: Path, session: Session) -> Dict[str, Any]:
    """Ingests a single batch JSON file into the database."""
    logger.info(f"Ingesting batch drop: {filepath.name}")
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_batch_id = data.get("batch_id")
    try:
        investigation_id = uuid.UUID(raw_batch_id) if raw_batch_id else uuid.uuid4()
    except (ValueError, TypeError):
        investigation_id = uuid.uuid4()

    query = data.get("query") or "Manual Ingestion"

    # Resolve or create Investigation
    investigation = session.query(Investigation).filter_by(id=investigation_id).first()
    if not investigation:
        investigation = Investigation(
            id=investigation_id,
            run_id=uuid.uuid4(),
            query=query,
            status="completed",
            created_at=datetime.now(timezone.utc),
        )
        session.add(investigation)
        session.flush()

    pages_data = data.get("pages", [])
    total_pages = 0
    total_new = 0
    total_merged = 0

    for p_data in pages_data:
        try:
            _, entities, new_cnt, merged_cnt = process_page(session, p_data, investigation_id)
            total_pages += 1
            total_new += new_cnt
            total_merged += merged_cnt
        except Exception as exc:
            logger.error(f"Error processing page {p_data.get('url')}: {exc}")

    investigation.page_count = (investigation.page_count or 0) + total_pages
    investigation.entity_count = (investigation.entity_count or 0) + (total_new + total_merged)
    session.commit()

    # Move processed file to archive
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    dest_path = PROCESSED_DIR / filepath.name
    shutil.move(str(filepath), str(dest_path))

    stats = {
        "batch_id": str(investigation_id),
        "query": query,
        "pages_processed": total_pages,
        "new_entities": total_new,
        "merged_entities": total_merged,
        "archived_to": str(dest_path),
    }
    logger.info(
        f"Batch {investigation_id} completed: {total_pages} pages, "
        f"{total_new} new entities, {total_merged} merged."
    )
    return stats


def run_once() -> List[Dict[str, Any]]:
    """Runs a single pass over data/drop/incoming/."""
    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(INCOMING_DIR.glob("*.json"))
    if not files:
        logger.info("No pending batch files in data/drop/incoming/.")
        return []

    _, session_factory = get_db_session()
    results = []
    with session_factory() as session:
        for f in files:
            try:
                res = ingest_batch_file(f, session)
                results.append(res)
            except Exception as e:
                logger.error(f"Failed to ingest file {f.name}: {e}")
                session.rollback()
    return results


def run_watcher(poll_interval: int = 5):
    """Continuous watcher polling data/drop/incoming/."""
    logger.info(f"Starting Jane Ingest Watcher (polling every {poll_interval}s)...")
    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    
    while True:
        try:
            files = sorted(INCOMING_DIR.glob("*.json"))
            if files:
                _, session_factory = get_db_session()
                with session_factory() as session:
                    for f in files:
                        try:
                            ingest_batch_file(f, session)
                        except Exception as e:
                            logger.error(f"Failed to ingest file {f.name}: {e}")
                            session.rollback()
        except Exception as loop_err:
            logger.error(f"Error in watcher loop: {loop_err}")
        time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(description="Jane Host Ingestion & Entity Extractor")
    parser.add_argument("--once", action="store_true", help="Process all pending batches and exit")
    parser.add_argument("--poll", type=int, default=5, help="Polling interval in seconds (default: 5)")
    args = parser.parse_args()

    if not HAS_VOIDACCESS:
        logger.error("Core database and extractor modules not found.")
        sys.exit(1)

    if args.once:
        results = run_once()
        print(json.dumps(results, indent=2))
    else:
        run_watcher(args.poll)


if __name__ == "__main__":
    main()
