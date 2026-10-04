"""
Jane Bridge — Host Ingestion Watcher
Monitors the shared drop directory on the Host machine,
validates incoming batch JSON drops from Whonix, and stages them for backend processing.
"""

import argparse
import json
import logging
from pathlib import Path
import shutil
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("jane.bridge.watcher")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
INCOMING_DIR = BASE_DIR / "data" / "drop" / "incoming"
PROCESSED_DIR = BASE_DIR / "data" / "drop" / "processed"
FAILED_DIR = BASE_DIR / "data" / "drop" / "failed"

def validate_batch(payload: dict) -> bool:
    required_keys = {"batch_id", "source_agent", "created_at", "pages"}
    if not required_keys.issubset(payload.keys()):
        logger.warning(f"Batch missing required keys. Has: {list(payload.keys())}")
        return False
    
    if not isinstance(payload.get("pages"), list):
        logger.warning("'pages' must be a list")
        return False

    return True

def process_single_batch(file_path: Path) -> bool:
    logger.info(f"Processing incoming drop: {file_path.name}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not validate_batch(data):
            logger.error(f"Validation failed for {file_path.name}")
            FAILED_DIR.mkdir(parents=True, exist_ok=True)
            shutil.move(str(file_path), str(FAILED_DIR / file_path.name))
            return False

        batch_id = data.get("batch_id")
        query = data.get("query")
        pages = data.get("pages", [])
        domains = {p.get("onion_address") for p in pages if p.get("onion_address")}

        logger.info(f"[SUCCESS] Ingested Batch {batch_id}")
        logger.info(f"          Query   : '{query}'")
        logger.info(f"          Pages   : {len(pages)}")
        logger.info(f"          Domains : {len(domains)} distinct onion domains")

        # Move to processed folder
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        dest = PROCESSED_DIR / file_path.name
        shutil.move(str(file_path), str(dest))
        logger.info(f"          Archived to: {dest.name}")
        return True

    except Exception as e:
        logger.error(f"Error processing {file_path.name}: {e}")
        FAILED_DIR.mkdir(parents=True, exist_ok=True)
        shutil.move(str(file_path), str(FAILED_DIR / file_path.name))
        return False

def scan_incoming() -> int:
    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    incoming_files = sorted(INCOMING_DIR.glob("batch_*.json"))
    processed_count = 0
    for file_path in incoming_files:
        if file_path.name.endswith(".tmp"):
            continue  # Skip files currently being written
        if process_single_batch(file_path):
            processed_count += 1
    return processed_count

def main():
    parser = argparse.ArgumentParser(description="Jane Bridge Ingestion Watcher")
    parser.add_argument("--once", action="store_true", help="Run a single scan pass and exit")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    args = parser.parse_args()

    logger.info("Starting Jane Bridge Watcher...")
    logger.info(f"Incoming directory : {INCOMING_DIR}")
    logger.info(f"Processed directory: {PROCESSED_DIR}")

    if args.once:
        count = scan_incoming()
        logger.info(f"Scan complete. Ingested {count} batches.")
    else:
        logger.info(f"Watching for new drops every {args.interval}s (Ctrl+C to stop)...")
        try:
            while True:
                scan_incoming()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("Watcher stopped by user.")

if __name__ == "__main__":
    main()
