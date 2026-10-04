"""
Jane Backend — Entity Extractor
Leverages VoidAccess's comprehensive, pre-compiled regex extraction engine
to extract intelligence entities (wallets, PGP, handles, emails, CVEs, hashes, IOCs)
from scraped page text and raw HTML.
"""

from dataclasses import dataclass, field
import logging
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger("jane.backend.extractor")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

try:
    from jane.backend.regex_patterns import (
        extract_all as _va_extract_all,
        BITCOIN_ADDRESS,
        ETHEREUM_ADDRESS,
        MONERO_ADDRESS,
        LITECOIN_ADDRESS,
        ZCASH_ADDRESS,
        DOGECOIN_ADDRESS,
        XRP_ADDRESS,
        SOLANA_ADDRESS,
        TRON_ADDRESS,
        BITCOIN_CASH_ADDRESS,
        DASH_ADDRESS,
        EMAIL_ADDRESS,
        PGP_KEY_BLOCK,
        CVE_NUMBER,
        IP_ADDRESS,
        PHONE_NUMBER,
        FILE_HASH_MD5,
        FILE_HASH_SHA1,
        FILE_HASH_SHA256,
        ONION_URL,
        MITRE_TECHNIQUE,
    )
    HAS_VOIDACCESS_EXTRACTOR = True
except Exception as e:
    logger.warning(f"Could not import regex_patterns: {e}. Using fallback patterns.")
    HAS_VOIDACCESS_EXTRACTOR = False

# Fallback basic regex patterns if VoidAccess import is unavailable
FALLBACK_PATTERNS = {
    "BITCOIN_ADDRESS": re.compile(r"\b(bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "MONERO_ADDRESS": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "ETHEREUM_ADDRESS": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "EMAIL_ADDRESS": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "PGP_KEY_BLOCK": re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----"),
    "CVE_NUMBER": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "IP_ADDRESS": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
}

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

_SANCTIONS_CACHE: Dict[str, Dict[str, Any]] = {}

def check_crypto_sanctions(address: str) -> Dict[str, Any]:
    """
    Checks crypto address against ChainQuery free sanctions API.
    Cached in memory. Never blocks on network failure.
    """
    import urllib.request
    import json

    clean_addr = address.strip()
    if clean_addr in _SANCTIONS_CACHE:
        return _SANCTIONS_CACHE[clean_addr]

    res = {"is_sanctioned": False, "sanctions": [], "checked": False}
    if not (clean_addr.startswith(("1", "3", "bc1", "0x")) and len(clean_addr) >= 26):
        _SANCTIONS_CACHE[clean_addr] = res
        return res

    url = f"https://chainquery.com/api/sanctions/check/{clean_addr}"
    req = urllib.request.Request(url, headers={"User-Agent": "Jane-Threat-Attribution/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                is_sanc = bool(data.get("sanctioned") or data.get("is_sanctioned"))
                sources = data.get("sources") or data.get("sanctions") or []
                res = {"is_sanctioned": is_sanc, "sanctions": sources, "checked": True}
    except Exception as exc:
        logger.debug(f"Sanctions check offline/timed out for {clean_addr}: {exc}")

    _SANCTIONS_CACHE[clean_addr] = res
    return res


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


@dataclass
class ExtractedEntity:
    entity_type: str
    value: str
    canonical_value: str
    confidence: float = 1.0
    context_snippet: str = ""
    is_sanctioned: bool = False


def extract_entities_from_text(text: str, context_window: int = 150) -> List[ExtractedEntity]:
    """Extracts all intelligence entities from a block of text with calibrated confidence."""
    if not text:
        return []

    results: List[ExtractedEntity] = []
    seen = set()

    if HAS_VOIDACCESS_EXTRACTOR:
        raw_matches = _va_extract_all(text)
        for etype, values in raw_matches.items():
            conf = ENTITY_CONFIDENCE_TABLE.get(etype, ENTITY_CONFIDENCE_TABLE["DEFAULT"])
            for val in values:
                if not val or len(val) > 5000:
                    continue
                canonical = val.strip()
                if etype in ("EMAIL_ADDRESS", "ONION_URL"):
                    canonical = canonical.lower()

                key = (etype, canonical)
                if key in seen:
                    continue
                seen.add(key)

                snippet = extract_context_snippet(text, val, window=context_window)
                is_sanc = False
                if etype in ("BITCOIN_ADDRESS", "ETHEREUM_ADDRESS"):
                    sanc_info = check_crypto_sanctions(canonical)
                    is_sanc = sanc_info["is_sanctioned"]

                results.append(ExtractedEntity(
                    entity_type=etype,
                    value=val.strip(),
                    canonical_value=canonical,
                    confidence=conf,
                    context_snippet=snippet,
                    is_sanctioned=is_sanc,
                ))
    else:
        for etype, pat in FALLBACK_PATTERNS.items():
            conf = ENTITY_CONFIDENCE_TABLE.get(etype, ENTITY_CONFIDENCE_TABLE["DEFAULT"])
            for match in pat.finditer(text):
                val = match.group(0).strip()
                key = (etype, val)
                if key in seen:
                    continue
                seen.add(key)

                snippet = extract_context_snippet(text, val, window=context_window)
                is_sanc = False
                if etype in ("BITCOIN_ADDRESS", "ETHEREUM_ADDRESS"):
                    sanc_info = check_crypto_sanctions(val)
                    is_sanc = sanc_info["is_sanctioned"]

                results.append(ExtractedEntity(
                    entity_type=etype,
                    value=val,
                    canonical_value=val.lower() if etype == "EMAIL_ADDRESS" else val,
                    confidence=conf,
                    context_snippet=snippet,
                    is_sanctioned=is_sanc,
                ))

    return results


def run_extraction(batch_data: Dict[str, Any]) -> Dict[str, Any]:
    """Microservice entrypoint: Extracts all intelligence entities from a Scout batch."""
    pages = batch_data.get("pages", [])
    extracted_by_page = []
    all_entities = []

    for page in pages:
        url = page.get("url", "")
        onion_address = page.get("onion_address", "")
        # Inspect cleaned text first, then raw HTML snippets
        text_corpus = f"{page.get('title', '')}\n{page.get('cleaned_text', '')}\n{page.get('raw_html', '')[:50000]}"
        entities = extract_entities_from_text(text_corpus)
        
        serialized_entities = [
            {
                "entity_type": e.entity_type,
                "value": e.value,
                "canonical_value": e.canonical_value,
                "confidence": e.confidence,
                "context_snippet": e.context_snippet[:150],
                "is_sanctioned": e.is_sanctioned,
            }
            for e in entities
        ]

        extracted_by_page.append({
            "url": url,
            "onion_address": onion_address,
            "entity_count": len(serialized_entities),
            "entities": serialized_entities,
        })
        all_entities.extend(serialized_entities)

    return {
        "status": "EXTRACTED",
        "batch_id": batch_data.get("batch_id", ""),
        "total_entities_found": len(all_entities),
        "pages_processed": len(pages),
        "results_by_page": extracted_by_page,
    }


def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Jane Extractor: Microservice for Cyber Indicator Extraction")
    parser.add_argument("--batch", "-b", type=str, help="Path to Scout batch JSON file")
    parser.add_argument("--text", "-t", type=str, help="Raw text string to extract entities from")
    args = parser.parse_args()

    if args.text:
        entities = extract_entities_from_text(args.text)
        print(json.dumps([e.__dict__ for e in entities], indent=2))
    elif args.batch:
        batch_path = Path(args.batch)
        if not batch_path.exists():
            print(f"Error: Batch file {args.batch} not found.")
            sys.exit(1)
        with open(batch_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        res = run_extraction(data)
        print(json.dumps(res, indent=2))
    else:
        print("Provide --batch <file> or --text <string>")
        sys.exit(1)


if __name__ == "__main__":
    main()
