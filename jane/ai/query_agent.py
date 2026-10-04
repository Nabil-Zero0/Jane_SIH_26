"""
jane/ai/query_agent.py — Read-Only AI Query Agent
Translates natural-language intelligence questions into clean SQL SELECT statements
operating strictly over the curated read views:
- v_actor_summary
- v_actor_identifiers
- v_marketplace_activity
- v_infrastructure_findings
- v_actor_trust_links
- v_actor_products
- v_clearnet_accounts

Has zero file/shell tools. Operates solely as a question-to-SQL translator.
All queries are subsequently validated and executed through the connection-level
read-only driver layer.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from jane.db.database import get_curated_schema_description

logger = logging.getLogger("jane.ai.query_agent")

OPENCODE_BASE_URL = os.environ.get("OPENCODE_API_URL", "http://127.0.0.1:4096")


def _synthesize_curated_view_sql(question: str) -> str:
    """
    Deterministic synthesis engine for common officer queries targeting
    the curated view schema. Serves as robust standalone translator or
    instant fallback when OpenCode server is offline.
    """
    q = question.lower().strip()

    # 1. Trust links / Vouched actors
    if any(k in q for k in ("trust", "vouch", "vouched", "trusted", "endorse")):
        return (
            "SELECT actor_handle, trusted_actor_handle, confidence, evidence_quote, created_at "
            "FROM v_actor_trust_links "
            "ORDER BY confidence DESC;"
        )

    # 2. Shared identifiers (pivots across 2+ actors)
    if any(k in q for k in ("shared", "multi-actor", "common wallet", "common identifier", "overlap")):
        return (
            "SELECT actor_id, primary_handle, identifier_type, identifier_value, is_shared, confidence, evidence_quote "
            "FROM v_actor_identifiers "
            "WHERE is_shared = 1 "
            "ORDER BY identifier_type, identifier_value;"
        )

    # 3. Specific identifier types (wallets, pgp, handles, emails, phones, ips)
    if any(k in q for k in ("wallet", "crypto", "bitcoin", "btc", "monero", "xmr", "eth", "solana", "pgp", "email", "phone")):
        clauses = []
        if any(c in q for c in ("wallet", "crypto", "bitcoin", "btc", "monero", "xmr", "eth", "solana")):
            clauses.append("identifier_type = 'wallet'")
        elif "pgp" in q:
            clauses.append("identifier_type = 'pgp'")
        elif "email" in q:
            clauses.append("identifier_type = 'email'")
        elif "phone" in q:
            clauses.append("identifier_type = 'phone'")

        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return (
            f"SELECT actor_id, primary_handle, identifier_type, identifier_value, is_shared, confidence, evidence_quote "
            f"FROM v_actor_identifiers "
            f"{where_clause} "
            f"ORDER BY confidence DESC;"
        )

    # 4. Clearnet accounts / OSINT pivots
    if any(k in q for k in ("clearnet", "osint", "github", "twitter", "social", "forum account", "platform")):
        return (
            "SELECT account_id, actor_id, primary_handle, platform, value, evidence_quote, created_at "
            "FROM v_clearnet_accounts "
            "ORDER BY primary_handle;"
        )

    # 5. Products / Commodities
    if any(k in q for k in ("product", "commodity", "sell", "goods", "merchandise", "dumps", "cards", "drugs", "weapons")):
        return (
            "SELECT actor_id, primary_handle, product_id, product_name, product_category, confidence, evidence_quote "
            "FROM v_actor_products "
            "ORDER BY confidence DESC;"
        )

    # 6. Infrastructure findings / Leaked IPs / Banners / Favicons
    if any(k in q for k in ("infra", "infrastructure", "banner", "favicon", "ip leak", "leaked ip", "finding")):
        clauses = []
        if "banner" in q:
            clauses.append("finding_type = 'banner'")
        elif "favicon" in q:
            clauses.append("finding_type = 'favicon_hash'")
        elif "ip" in q:
            clauses.append("finding_type = 'ip_leak'")

        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return (
            f"SELECT finding_id, marketplace_id, onion_domain, finding_type, value, evidence_quote, found_at "
            f"FROM v_infrastructure_findings "
            f"{where_clause} "
            f"ORDER BY found_at DESC;"
        )

    # 7. Marketplace activity
    if any(k in q for k in ("market", "marketplace", "marketplaces", "hidden service", "onion domain", "site")):
        return (
            "SELECT marketplace_id, onion_domain, display_name, category, actor_count, infrastructure_findings_count, first_seen, last_seen "
            "FROM v_marketplace_activity "
            "ORDER BY actor_count DESC, infrastructure_findings_count DESC;"
        )

    # 8. Threat actors / Actor summary (default for actor queries)
    clauses = []
    if "carding" in q:
        clauses.append("category LIKE '%Carding%'")
    elif "fraud" in q:
        clauses.append("category LIKE '%Fraud%'")
    elif "cyber" in q:
        clauses.append("category LIKE '%Cyber%'")

    if any(c in q for c in ("high confidence", "confidence >= 0.8", "confidence > 0.8")):
        clauses.append("attribution_confidence >= 0.8")

    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return (
        f"SELECT actor_id, primary_handle, category, attribution_confidence, alias_count, marketplace_count, product_count, first_seen, last_seen "
        f"FROM v_actor_summary "
        f"{where_clause} "
        f"ORDER BY attribution_confidence DESC;"
    )


def generate_sql_for_question(question: str) -> str:
    """
    Translates natural-language question into SQL text.
    First attempts OpenCode AI agent completion if available;
    falls back cleanly to deterministic view synthesis.
    Strips code fences and enforces single statement SELECT.
    """
    cleaned_q = (question or "").strip()
    if not cleaned_q:
        return "SELECT * FROM v_actor_summary LIMIT 25;"

    # Attempt OpenCode completion if endpoint responsive
    try:
        schema_prompt = get_curated_schema_description()
        req_payload = {
            "model": "opencode",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a dedicated read-only Threat Intelligence SQL generator. "
                        "Translate the user's question into a single SQLite SELECT statement. "
                        "Query ONLY from the following curated views:\n"
                        f"{schema_prompt}\n"
                        "Return ONLY the raw SQL query. No explanations, no markdown formatting."
                    ),
                },
                {"role": "user", "content": cleaned_q},
            ],
            "max_tokens": 250,
            "temperature": 0.0,
        }
        req = urllib.request.Request(
            f"{OPENCODE_BASE_URL}/v1/chat/completions",
            data=json.dumps(req_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw_sql = data["choices"][0]["message"]["content"].strip()
            # Clean markdown code blocks
            clean_sql = re.sub(r"^```(?:sql)?\s*", "", raw_sql, flags=re.IGNORECASE)
            clean_sql = re.sub(r"\s*```$", "", clean_sql).strip()
            if clean_sql.upper().startswith("SELECT") or clean_sql.upper().startswith("WITH"):
                return clean_sql
    except Exception as exc:
        logger.debug(f"OpenCode query agent offline or timed out ({exc}), using view synthesizer")

    # Deterministic synthesis over curated views
    return _synthesize_curated_view_sql(cleaned_q)
