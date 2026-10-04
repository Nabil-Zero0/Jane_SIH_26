"""
Jane AI Engine — OpenCode Bridge & Forensic Profiler
Creates isolated target workspaces (no repo confusion) and invokes OpenCode
to analyze dark web HTML + heuristics, outputting structured evidence quotes and graph links.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import urllib.error
import urllib.request
import urllib.parse
import time

logger = logging.getLogger("jane.ai.opencode")

OPENCODE_BASE_URL = "http://127.0.0.1:4096"

OPENCODE_MODEL = "muse-spark-1.3-contributor-free"

# Configurable OpenCode phase timeouts (defaults: Turn 1: 60s, Turn 2: 120s, Turn 2.5: 60s, Turn 3: 180s)
TIMEOUT_TURN1_FANOUT: int = int(os.environ.get("JANE_TIMEOUT_TURN1", 160))
TIMEOUT_TURN2_ATTRIBUTION: int = int(os.environ.get("JANE_TIMEOUT_TURN2", 320))
TIMEOUT_TURN25_OSINT: int = int(os.environ.get("JANE_TIMEOUT_TURN25", 160))
TIMEOUT_TURN3_GRAPH: int = int(os.environ.get("JANE_TIMEOUT_TURN3", 420))
TIMEOUT_TURN35_MERMAID: int = int(os.environ.get("JANE_TIMEOUT_TURN35", 120))



from jane.ai.harness import (
    ensure_investigation_harness,
    ensure_sql_studio_harness,
)
from jane.backend.graph.mermaid import validate_mermaid_syntax


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def create_investigation_workspace(
    investigation_id: str,
    query: str,
    root: Optional[Path] = None,
    extra_prompt: str = "",
) -> Path:
    """Create the standardized, query-scoped evidence package before collection starts."""
    workspace = root or (Path(__file__).resolve().parent.parent / "data" / "investigations")
    inv_dir = workspace / investigation_id
    return ensure_investigation_harness(
        workspace_path=inv_dir,
        investigation_id=investigation_id,
        query=query,
        extra_prompt=extra_prompt,
    )


def update_investigation_workspace(workspace: Path, **updates: Any) -> None:
    for filename in ("job_meta.json", "investigation.json"):
        path = workspace / filename
        current = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        current.update(updates)
        _write_json(path, current)


def write_investigation_artifacts(
    workspace: Path,
    pages: List[Dict[str, Any]],
    analyses: Dict[str, Any],
    chunks: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Project deterministic pipeline output into the standardized OpenCode workspace."""
    artifacts: List[Dict[str, Any]] = []
    (workspace / "html").mkdir(parents=True, exist_ok=True)
    for index, page in enumerate(pages, 1):
        url = page.get("url", "")
        target_id = "target_" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
        target_dir = workspace / "pages" / target_id
        target_dir.mkdir(parents=True, exist_ok=True)
        raw = page.get("raw_html", "")
        raw_path = target_dir / "raw.html"
        raw_path.write_text(raw, encoding="utf-8")
        if raw:
            (workspace / "html" / f"{target_id}.html").write_text(raw, encoding="utf-8")
        (target_dir / "cleaned.txt").write_text(page.get("cleaned_text", ""), encoding="utf-8")
        _write_json(target_dir / "metadata.json", {k: v for k, v in page.items() if k not in {"raw_html", "cleaned_text"}})
        _write_json(target_dir / "headers.json", page.get("response_headers", page.get("headers", {})))
        _write_json(target_dir / "links.json", {"outbound_links": page.get("outbound_links", [])})
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        artifacts.append({"kind": "raw_html", "path": str(raw_path.relative_to(workspace)), "page_id": target_id, "sha256": digest})

    # Standardized architecture folders
    _write_json(workspace / "extracted/indicators.json", analyses.get("extractor", {}))
    _write_json(workspace / "extracted/evidence_chunks.json", chunks or [])
    _write_json(workspace / "locksmith/findings.json", analyses.get("locksmith", {}))
    _write_json(workspace / "stylometry/profile.json", analyses.get("stylometry", {}))

    # Compatibility mirrors
    _write_json(workspace / "analysis/extractor.json", analyses.get("extractor", {}))
    _write_json(workspace / "analysis/locksmith.json", analyses.get("locksmith", {}))
    _write_json(workspace / "analysis/stylometry.json", analyses.get("stylometry", {}))
    _write_json(workspace / "analysis/site_profiles.json", analyses.get("site_profiles", {}))
    _write_json(workspace / "analysis/evidence_chunks.json", chunks or [])
    _write_json(workspace / "manifest.json", {"investigation_id": workspace.name, "artifacts": artifacts})
    return {"investigation_id": workspace.name, "artifacts": artifacts}


# ---------------------------------------------------------------------------
# Multi-Turn Prompts for OpenCode Session
# ---------------------------------------------------------------------------

def _fanout_instruction(workspace: Path, query: str, fanout_count: int) -> str:
    out_file = workspace / "queries" / "fanout.json"
    return f"""# NTRO Investigation Query Expansion

Subject: "{query}"
Count: {fanout_count}
Output file: `{out_file}`

## ROLE
You are a defensive cybersecurity threat-intelligence query expansion agent. Create focused search queries for Ahmia and similar dark-web search engines.

## RULES
1. Generate exactly {fanout_count} queries.
2. Every other query must be a meaningful variation of the original investigation intent.
3. Use only information present in the original query or safe, standard terminology directly related to it.
4. Useful expansions may include synonyms, technical terms, threat context, sector terms, geography, language variants, or common abbreviations—but only when justified.
5. Do NOT invent actors, aliases, organizations, domains, locations, products, incidents, or other facts.
6. Keep queries short and search-engine-friendly.
7. Do not create duplicates, trivial word rearrangements, generic queries, or unrelated combinations.
8. Give each query a short purpose label such as `"synonym"`, `"threat_context"`, `"sector"`, `"geography"`, or `"language"`.
9. Return ONLY valid JSON. No Markdown, comments, explanations, or extra text.

## OUTPUT
Write the JSON to `{out_file}` using exactly this structure:

{{
  "original_query": "{query}",
  "queries": [
    {{"text": "query text", "purpose": "some purpose"}}
  ]
}}

## EXAMPLE
Input: "ransomware group selling stolen healthcare data"
Count: 2

{{
  "original_query": "ransomware group selling stolen healthcare data",
  "queries": [
    {{"text": "ransomware healthcare data leak", "purpose": "synonym"}},
    {{"text": "healthcare ransomware extortion", "purpose": "threat_context"}}
  ]
}}

Before outputting, verify: exact count, no invented facts, no duplicates, valid JSON only."""



def _evidence_instruction(workspace: Path) -> str:
    return f"""# NTRO Investigation Evidence Attribution Directive — Phase 2

Investigation Workspace: {workspace}
Output File: `{workspace / 'opencode' / 'attribution_report.json'}`

## ROLE
You are a Senior Intelligence Analyst conducting defensive cyber threat-intelligence analysis for NTRO. The collection phase is complete. Your task is to analyze the supplied evidence, identify entities and relationships, and produce an evidence-grounded attribution report.

## EVIDENCE SOURCES
Analyze ALL relevant files available in this workspace:
- `pages/*/cleaned.txt` — stripped, human-readable page text. PRIMARY source for textual analysis and verbatim quotes.
- `html/` — raw captured HTML files. Secondary source for raw layout, metadata, or hidden text.
- `manifest.json` — index of all crawled onion hidden services and target page IDs.
- `pages/*/metadata.json` — site titles, captured URLs, and HTTP status.
- `extracted/indicators.json` — pre-extracted crypto wallets, PGP keys, emails, and handles.
- `extracted/evidence_chunks.json` — pre-sliced, traceable text evidence chunks.
- `locksmith/findings.json` — server banners, favicon mmh3 hashes, and network leaks.
- `stylometry/profile.json` — writing-style vectors, Burrows' Delta comparisons, and OpSec scores.
- `queries/fanout.json` — the search queries used to discover these pages.

Do not assume an extracted indicator or automated finding is correct merely because it appears in a supporting file. Cross-check important findings against the available evidence.

## CORE RULES

1. **Evidence before inference.** Report only conclusions supported by the collected evidence.
2. **Never invent attribution.** Do not create actors, aliases, marketplace names, commodities, relationships, quotes, or facts that are not supported by the evidence.
3. **Exact quotations.** For EVERY identified threat actor, commodity, wallet, and graph relationship, provide an exact verbatim quote from the relevant `html/` file whenever textual evidence exists. Preserve the original wording; do not paraphrase inside `evidence_quote`.
4. If a claim is supported only by metadata, headers, indicators, hashes, or stylometry and has no suitable HTML quotation, do not fabricate a quote. Use the strongest available evidence and reflect the limitation in `stylometric_notes` or the relevant relationship assessment.
5. **Distinguish identity from similarity.** A shared wallet, PGP key, handle, infrastructure characteristic, or writing style may indicate a relationship but does NOT by itself prove that two identities are the same person or actor.
6. Stylometry is supporting evidence, not definitive attribution. Treat Burrows' Delta and OpSec scores as indicators of similarity or differentiation, not proof of identity.
7. Infrastructure overlap (favicon hashes, banners, hosting, InternetDB findings) must be described as an observed technical relationship, not automatically as proof of common ownership.
8. Do not treat advertisements, quoted text, user comments, copied material, or third-party claims as statements made by the investigated actor unless the evidence establishes authorship.
9. Prefer the narrowest defensible conclusion. If evidence is ambiguous, say so.
10. If the available evidence is insufficient to identify an actor, marketplace, commodity, or relationship, omit the unsupported entity rather than guessing.

## REQUIRED ANALYSIS

Determine, where supported by evidence:
- Primary threat actors and vendor aliases.
- Marketplace, forum, or service name.
- Illicit commodities/services.
- Relevant wallets and other indicators.
- Meaningful relationships between identified entities.
- Supporting infrastructure or technical overlaps.
- Useful stylometric observations.

For each actor, distinguish the **observed handle/identity** from your assessment of their role. Use roles such as `Lead Vendor`, `Administrator`, `Moderator`, `Buyer`, or `Unknown` only when supported.

For each graph relationship, ensure BOTH the source and target are identifiable entities supported by the evidence. Do not create relationships merely because two indicators appear in the same file.

## THREAT ACTORS

Extract every identifiable entity that appears to conduct, operate, sell, provide, advertise, administer, or otherwise directly participate in the observed illicit activity.

A threat actor may be:
- a person's name
- an organization or group name
- a vendor name
- an alias, nickname, username, or handle
- a pseudonym
- an otherwise unidentified named entity associated with the activity

Do NOT require the entity to be a confirmed real-world identity. Preserve the name exactly as observed and do not attempt to resolve an alias to a real person unless the evidence explicitly supports it.

Important: not every name mentioned on a page is a threat actor. Do not classify customers, victims, quoted third parties, products, services, locations, or unrelated organizations as actors unless the evidence shows they participate in the illicit activity.

If a page states that "ShadowFox" operates the marketplace, extract `ShadowFox` as a threat actor.

If a page states "John Doe sells stolen cards", extract `John Doe` as a threat actor.

If a page states "ACME Bank credentials for sale", do NOT automatically classify `ACME Bank` as a threat actor; it may be the victim or referenced organization.

If the actor's role is unclear, use `"role": "Unknown"` rather than omitting a clearly identified actor.

For every extracted actor, provide the exact supporting quotation from the HTML.

## THREAT CATEGORY

Determine the threat category from the collected evidence. Do NOT restrict the category to a predefined list.

Use a concise, specific category that accurately describes the observed activity, for example:
- Financial Fraud / Carding
- Narcotics
- Cybercrime
- Credential Theft
- Malware
- Initial Access
- Data Breach / Data Sale
- Counterfeiting
- Weapons
- Fraud
- Money Laundering
- or another appropriate category supported by the evidence.

Do not invent a category unrelated to the evidence. If the evidence clearly supports multiple distinct threat types, use a concise combined category.

If the evidence is insufficient to determine what type of activity is occurring, use:
`INSUFFICIENT_EVIDENCE`

Do not use `INSUFFICIENT_EVIDENCE` merely because the actor's identity is unknown. An unidentified actor can still have a well-supported threat category.

## CONFIDENCE

For graph links and observations, use a numeric confidence from `0.0` to `1.0` based on the strength and directness of the evidence:
- `0.90–1.00`: explicit, direct evidence
- `0.70–0.89`: strong corroborated evidence
- `0.40–0.69`: plausible but incomplete evidence
- `<0.40`: weak evidence; normally omit the relationship

Confidence reflects evidence strength, NOT the probability that an individual is guilty or the certainty of legal attribution.

## COMMODITIES & PRODUCT OBSERVATIONS

Turn 2 must distinguish between:
1. **Conceptual Product:** The normalized conceptual product/entity (e.g., "Fullz Credit Card Dumps").
2. **Product Observation / Listing:** A specific occurrence of that product on a specific source page/investigation.

Do NOT force every listing into a single normalized product if the evidence does not support that equivalence. Preserve the original source terminology.

### Extraction Rules:
- **Product Name (`name`):** Extract the normalized conceptual product name as directly supported by the source.
- **Original Title (`original_title`):** Preserve the literal listing headline/title as written on the page separately from the normalized name.
- **Category (`category`):** Use an appropriate category supported by the source (e.g., "Carding", "Narcotics", "Data Leak"). Do not invent categories.
- **Aliases (`aliases`):** ONLY emit aliases when the evidence explicitly supports that they refer to the same product. Do not create aliases merely because two names are semantically similar.
- **Pricing (`price`, `currency`):**
  - Extract numeric price (as float or null) and source currency (e.g. "USD", "BTC", "EUR", "XMR").
  - Do NOT convert currencies. Preserve source currency.
  - Do NOT confuse product price with escrow fees, shipping fees, vendor deposits, commission, wallet balances, or unrelated numbers.
  - If multiple distinct prices/tiers exist, emit distinct product observation entries where appropriate.
- **Quantity & Unit (`quantity`, `unit`):**
  - Extract numeric `quantity` (e.g., 100) and string `unit` (e.g., "cards", "accounts", "grams", "pills") ONLY when explicitly stated in source text.
  - Do NOT infer a unit from product category.
  - Do NOT turn arbitrary numbers in descriptions into quantities.
- **Minimum Order (`min_order`):**
  - Extract numeric minimum order quantity (MOQ) only when explicitly stated (e.g., "MOQ: 10", "minimum purchase: 50").
  - Do not confuse available stock with minimum order.
- **Availability & Status (`availability`, `listing_status`):**
  - `availability`: Extract explicit signals ("in stock", "out of stock", "sold out", "unavailable", or null).
  - `listing_status`: Extract explicit status ("active", "closed", "expired", or null). Do not infer "active" merely because the page was crawled.
- **Observation Date (`observation_date`):**
  - If the source explicitly contains a listing date, posted date, or marketplace timestamp, capture it (e.g. "2026-03-15").
  - Otherwise leave `observation_date: null`. NEVER use the crawl or ingestion timestamp as an observation date.
- **Marketplace & Provenance (`marketplace_name`, `onion_url`, `listing_url`, `vendor_handle`):**
  - Preserve the marketplace and vendor associated with each specific observation.
- **Evidence Quote (`evidence_quote`):**
  - EVERY extracted product observation MUST include an exact verbatim quote from the HTML or cleaned text directly supporting the price, quantity, and product details.
- **Uncertainty (`uncertainty`):**
  - If pricing, quantity, or identity equivalence is ambiguous, record the limitation in `uncertainty`.
- **Deduplication Doctrine:**
  - OpenCode must NOT perform authoritative cross-listing product deduplication. Never merge products solely because names are similar, descriptions match, or they share a marketplace/vendor. Preserve uncertainty.

## OUTPUT

Write ONLY valid JSON to:
`{workspace / 'opencode' / 'attribution_report.json'}`

Use exactly this structure:

{{
  "investigation_id": "{workspace.name}",
  "marketplace_name": "...",
  "threat_category": "Financial Fraud / Carding | Narcotics | Cybercrime | Counterfeiting | INSUFFICIENT_EVIDENCE",
  "threat_actors": [
    {{
      "designated_id": "TA-01",
      "primary_handle": "...",
      "role": "...",
      "evidence_quote": "Exact verbatim quote from html"
    }}
  ],
  "commodities": [
    {{
      "name": "...",
      "original_title": "...",
      "category": "...",
      "marketplace_name": "...",
      "onion_url": "http://...onion",
      "listing_url": "http://...onion/listing/123",
      "vendor_handle": "...",
      "price": 150.0,
      "currency": "USD",
      "quantity": 10.0,
      "unit": "cards",
      "min_order": 5.0,
      "availability": "in stock",
      "listing_status": "active",
      "observation_date": null,
      "aliases": [],
      "confidence": 0.95,
      "evidence_quote": "Exact verbatim quote from cleaned.txt or html",
      "uncertainty": null
    }}
  ],
  "graph_links": [
    {{
      "source": "...",
      "target": "...",
      "relation": "OPERATES | SELLS | USES | HOSTED ON",
      "confidence": 0.90,
      "evidence_quote": "Exact verbatim quote from html"
    }}
  ],
  "stylometric_notes": "Evidence-grounded observations and limitations."
}}

## FINAL VALIDATION

Before writing the file, verify:
- Every reported actor and commodity has supporting evidence.
- Every quotation is copied verbatim from the relevant HTML.
- No actor, alias, relationship, or fact was invented.
- Graph relationships have identifiable source and target entities.
- Confidence values are between 0.0 and 1.0.
- Stylometry and infrastructure findings are not presented as definitive identity attribution.
- `INSUFFICIENT_EVIDENCE` is used when evidence does not support a reliable conclusion.
- The output is valid JSON and contains no Markdown or explanatory text outside the JSON.
"""


def _osint_instruction(workspace: Path) -> str:
    """Build the Turn 2.5 prompt that makes OpenCode emit schema-v2 osint/targets.json."""
    attr_report = workspace / "opencode" / "attribution_report.json"
    indicators  = workspace / "extracted" / "indicators.json"
    out_file    = workspace / "osint" / "targets.json"
    inv_id      = workspace.name

    schema_example = (
        '{\n'
        '  "schema_version": "2.0",\n'
        f'  "investigation_id": "{inv_id}",\n'
        '  "targets": [\n'
        '    {\n'
        '      "target_id": "osint_001",\n'
        '      "associated_actor": "TA-01",\n'
        '      "identifier": "@torverified",\n'
        '      "normalized_identifier": "torverified",\n'
        '      "type": "username",\n'
        '      "platform_hints": ["telegram"],\n'
        '      "target_role": "contact",\n'
        '      "priority": "high",\n'
        '      "confidence": 0.91,\n'
        '      "reason": "Identifier explicitly presented as actor\'s external contact.",\n'
        '      "evidence": [\n'
        '        {\n'
        '          "source_type": "darknet_page",\n'
        '          "page_id": "page_042",\n'
        '          "quote": "Contact me on Telegram: @torverified"\n'
        '        }\n'
        '      ]\n'
        '    }\n'
        '  ]\n'
        '}'
    )
    empty_example = (
        '{"schema_version": "2.0", '
        f'"investigation_id": "{inv_id}", '
        '"targets": []}'
    )

    return (
        f"# NTRO OSINT Target Extraction Directive (Phase 2.5)\n\n"
        f"Investigation Workspace: {workspace}\n"
        f"Target Output File: `{out_file}`\n\n"
        f"CONTEXT FILES TO READ:\n"
        f"- `{attr_report}`: Phase 2 attribution report (threat actors, designated_ids)\n"
        f"- `{indicators}`: Pre-extracted indicators (handles, emails, Telegram, PGP)\n"
        f"- `html/`: Raw crawled HTML — primary evidence\n\n"
        "## MISSION\n\n"
        "Identify externally searchable identity clues associated with discovered threat actors.\n"
        "These are SEARCH TARGETS passed to a clearnet OSINT tool (Maigret).\n\n"
        "You are selecting search targets, NOT performing final attribution.\n"
        "Finding a username on GitHub does NOT mean that account belongs to the actor.\n\n"
        "## PROCESS\n\n"
        f"1. Read `{attr_report}` — identify threat actors, vendor handles from product listings, and designated_ids (e.g. TA-01).\n"
        f"2. Read `{indicators}` — extract handles, emails, Telegram addresses, PGP identities.\n"
        "3. Select each externally searchable identifier ONLY if literally present in the evidence.\n"
        "4. Associate each target with the relevant actor using that actor's designated_id.\n"
        "5. Provide the verbatim quote and page reference that justifies selection.\n"
        f"6. Write strictly valid JSON to `{out_file}`.\n\n"
        "## CRITICAL RULES\n\n"
        "1. Do NOT invent, guess, or infer identifiers, usernames, emails, aliases, or accounts.\n"
        "2. Do NOT associate a target with an actor unless evidence directly links them.\n"
        "3. An empty targets array is valid and correct when no searchable clues exist.\n"
        "4. An OSINT search result is NOT proof of actor identity — Maigret discovery is an investigative lead, not proof of identity. Never automatically attribute a clearnet account to a vendor merely because usernames match.\n"
        "5. Output ONLY valid JSON. No markdown, prose, or comments outside the JSON.\n\n"
        "## FIELD REFERENCE\n\n"
        "type: username | email | PGP_identity | forum_handle | marketplace_handle | contact_identifier | alias\n"
        "target_role: contact | alias | username | email | PGP_identity | marketplace_handle | forum_handle | vendor_handle\n"
        "priority: high | medium | low\n"
        "confidence: evidence strength linking identifier to actor (NOT confidence in Maigret results)\n"
        "  0.85-1.00 explicit direct | 0.65-0.84 strong contextual | 0.40-0.64 plausible | <0.40 omit\n\n"
        "## OUTPUT SCHEMA\n\n"
        f"Write ONLY valid JSON to `{out_file}`:\n\n"
        f"{schema_example}\n\n"
        "BEFORE WRITING — verify:\n"
        "- Every identifier is literally present in collected evidence.\n"
        "- Every evidence quote is verbatim.\n"
        "- associated_actor matches a designated_id from the attribution report.\n"
        "- target_id is unique in this file (osint_001, osint_002, ...).\n"
        "- normalized_identifier strips leading @ and URL prefixes to bare searchable value.\n"
        "- platform_hints is a JSON array (may be []).\n"
        "- confidence is a float between 0.0 and 1.0.\n"
        "- priority is exactly 'high', 'medium', or 'low'.\n"
        f"- If no valid targets exist write: {empty_example}\n"
    )


def _graph_instruction(workspace: Path) -> str:
    """Turn 3: instructs OpenCode to produce ONLY structured graph JSON from evidence.

    OpenCode's role here is DATA EXTRACTION — it outputs a structured JSON
    object that our fixed Cytoscape renderer will consume. It must NOT write
    any Cytoscape configuration, Python code, TypeScript, or prose description.
    It must NOT invent entities not literally present in the evidence text.
    """
    attr_report = workspace / "opencode" / "attribution_report.json"
    indicators = workspace / "extracted" / "indicators.json"
    clearnet_summary = workspace / "osint" / "clearnet_summary.json"
    return f"""# NTRO Threat Intelligence Relationship Graph — Phase 3
# Comprehensive Investigation Graph Synthesis

Investigation Workspace: {workspace}
Output File: `{workspace / 'graph' / 'threat_graph.json'}`

## MISSION

Construct the COMPLETE evidence-grounded graph of this investigation.

The graph is the primary visual representation of the case. A human investigator should be able to understand, at a glance:

WHO is involved, WHERE they operate, WHAT they sell or provide, WHICH victims or organizations are involved, WHICH accounts and identifiers they use, WHAT infrastructure they control, WHICH tools/malware/data they reference, and HOW these entities are connected.

Do not summarize or simplify away useful relationships. Extract every meaningful, evidence-supported entity and relationship.

## READ FIRST

- `{attr_report}` — Phase 2 attribution and evidence analysis
- `{indicators}` — extracted IOCs and identifiers
- `{clearnet_summary}` — clearnet OSINT findings
- `html/` — raw crawled HTML; primary source for textual evidence

Use all sources. When sources conflict, prefer direct raw evidence and preserve uncertainty.

## CANONICAL GRAPH CONTRACT

The validator enforces a strict schema. Only the following node and edge types are accepted:

### CANONICAL NODE TYPES:
- `actor`: Person, vendor, operator handle, alias, or administrator persona.
- `marketplace`: Onion marketplace, forum, leak site, or darknet platform.
- `product`: Illicit commodity, service, dataset, or listing observed in the evidence.
- `shared_identifier`: Technical identifier (BTC/XMR wallet, PGP key, email, Telegram) explicitly shared by at least two distinct actors.
- `clearnet_account`: Clearnet account profile discovered via OSINT pivot (Maigret).

Do NOT emit any other node types (such as "organization", "website", "wallet", "domain", "evidence", "lead", "person").

### CANONICAL EDGE TYPES:
- `operates_on`: Actor -> Marketplace (evidence shows actor operates, administers, or moderates the site).
- `sells`: Actor -> Product (evidence shows actor sells, offers, or provides the product).
- `listed_on`: Product -> Marketplace (evidence shows product is listed, cataloged, or available on the marketplace).
- `shares_identifier`: Actor <-> Actor via SharedIdentifier node (explicit shared crypto wallet, PGP key, or contact handle).
- `trust`: Actor <-> Actor (requires explicit vouch, verification, endorsement, or trusted relationship keyword in evidence_quote).
- `clearnet_alias`: Actor -> ClearnetAccount (links threat actor to external pivot profile).

Do NOT emit any other edge types. Every edge MUST have an exact `evidence_quote` and numeric `confidence`.

Use `marketplace` for every site/forum/market node. Use `shared_identifier` only for an identifier explicitly shared by at least two actors. Use `clearnet_account` for Maigret profiles. Never emit `same_as`; deterministic graph code handles cross-investigation resolution.

## IDENTIFIER RULE

Wallets, PGP keys, emails, handles, usernames, and similar identifiers are important graph entities.

Create them as nodes when they are meaningful to the investigation.

If the SAME identifier is explicitly associated with multiple actors, retain ONE identifier node and connect every supported actor to it. This makes shared infrastructure immediately visible.

Never merge two identifiers merely because they look similar.

## ACTOR RULE

Extract every named person, organization, group, vendor, alias, handle, administrator, operator, or persona that the evidence associates with conducting, facilitating, selling, administering, or participating in the observed activity.

Do not require a real-world identity.

However, a name mentioned on a page is NOT automatically an actor. Victims, customers, products, referenced organizations, journalists, quoted third parties, and unrelated people must not be classified as actors without supporting evidence.

## EVIDENCE RULES

1. Every node and edge must be supported by collected evidence.
2. Every edge MUST contain `confidence` and an exact `evidence_quote`.
3. Every important entity should contain an exact supporting `evidence_quote`.
4. Prefer raw HTML for quotations.
5. Never fabricate or paraphrase quotations.
6. Do not turn similarity into identity.
7. Stylometry, shared infrastructure, wallets, handles, or writing style may support an association but do not automatically prove that two actors are the same person.
8. `same_as` requires explicit or exceptionally strong evidence.
9. Trust requires an explicit statement such as a vouch, verification, endorsement, or trusted relationship.
10. Do not create nodes for scraping artifacts, CSS, fonts, images, navigation elements, or generic hyperlinks.
11. Preserve exact identifiers and complete domains. Never truncate values.
12. If evidence is ambiguous, keep the entity but lower confidence or omit the unsupported relationship.
13. Do not invent missing fields. Use empty arrays or `"Unknown"` where appropriate.

## GRAPH COMPLETENESS

Carry forward ALL supported entities from Phase 2.

Do not omit an actor because they have no relationships.
Do not omit a product because its seller is unknown.
Do not omit a wallet because it is associated with only one actor.
Do not omit a site because it has only one discovered relationship.

The graph should contain both highly connected entities and legitimate isolated entities.

Create every directly supported relationship. Prefer a specific edge over `associated_with` or `connected_to`.

## CONFIDENCE

Use `0.90–1.00` for explicit direct evidence.
Use `0.70–0.89` for strong corroborated evidence.
Use `0.40–0.69` for plausible but incomplete evidence.
Use below `0.40` only when the weak relationship is still useful and explicitly supported.

Confidence describes EVIDENCE STRENGTH, not guilt, identity certainty, or legal culpability.

## OUTPUT

Write ONLY valid JSON to:

`{workspace / 'graph' / 'threat_graph.json'}`

Top-level structure:

{{
  "investigation_id": "{workspace.name}",
  "nodes": [],
  "edges": []
}}

Every node must contain at minimum:
`id`, `type`

Every edge must contain:
`source`, `target`, `type`, `confidence`, `evidence_quote`

Before writing the file, verify:

- Every supported Phase 2 actor is present.
- Every supported site/marketplace/forum is present.
- Every commodity/product/service is present.
- Relevant identifiers, accounts, infrastructure, datasets, malware, organizations, and other evidence entities are represented.
- Important relationships are not hidden inside node attributes when they can be represented as edges.
- Every edge references existing node IDs.
- No duplicate entity nodes were created unnecessarily.
- No unsupported relationships were inferred.
- Quotations are exact.
- Domains and identifiers are complete and untruncated.
- JSON is syntactically valid.
- Output contains JSON ONLY.
"""


def _mermaid_instruction(workspace: Path) -> str:
    """Turn 3.5: Instructs OpenCode to synthesize an executive Mermaid diagram."""
    baseline = workspace / "graph" / "mermaid.deterministic.mmd"
    threat_graph = workspace / "graph" / "threat_graph.json"
    attr_report = workspace / "opencode" / "attribution_report.json"
    targets_file = workspace / "osint" / "targets.json"
    out_file = workspace / "graph" / "mermaid.mmd"
    return f"""# NTRO Executive Investigation Map — Mermaid Synthesis (Phase 3.5)

Investigation Workspace: {workspace}
Input Baseline Diagram: `{baseline}`
Input Threat Graph: `{threat_graph}`
Input Attribution: `{attr_report}`
Input OSINT Targets: `{targets_file}`
Target Output File: `{out_file}`

## MISSION
Synthesize an executive-level Mermaid flowchart that summarizes the entire investigation at a single glance for senior leadership.
Transform the raw baseline diagram into a clean, intuitive, high-signal investigation map (10 to 25 nodes maximum).

## VISUAL HIERARCHY & NODE CONVENTIONS
Use distinct Mermaid node shapes to distinguish entity classes:
- Marketplaces / Platforms: `id[("Marketplace: <Name>")]`
- Threat Actors / Vendors: `id(["Actor: <Handle> (<Role>)"])`
- Commodities / Listings: `id["Product: <Name> (<Price if known>)"]`
- Wallets / Crypto / PGP: `id{{"Identifier: <Type> <Value>"}}`
- Clearnet OSINT Leads: `id[["OSINT Lead: <Platform> <Account>"]]`

## EDGE CONVENTIONS
- Direct relationships: `id1 -->|"SELLS / OPERATES / USES"| id2`
- Unconfirmed OSINT pivot leads: `id1 -.->|"LEAD: OSINT PIVOT"| id2`

## SYNTAX RULES (CRITICAL)
1. Start with `flowchart TD` on line 1.
2. Safe node IDs: alphanumeric and underscores only (e.g. `mkt_1`, `vendor_alpha`, `prod_dump`, `btc_wallet`, `osint_tg`).
3. Always wrap labels in quotes: `node_id["label"]`.
4. Escape or avoid any special characters like quotes or brackets inside labels.
5. Write ONLY valid Mermaid diagram text to `{out_file}`.
6. NO markdown code blocks (do NOT wrap in ```mermaid). Output raw diagram lines only.
"""


def create_investigation_session(workspace: Path) -> Optional[str]:
    """Create one persistent OpenCode session for the investigation."""
    try:
        workspace_dir = str(workspace.resolve())
        create_req = urllib.request.Request(
            f"{OPENCODE_BASE_URL}/session",
            data=json.dumps({
                "title": f"Jane Investigation - {workspace.name}",
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(create_req, timeout=5) as resp:
            session_id = json.loads(resp.read().decode("utf-8")).get("id")
        if not session_id:
            return None
        session_meta = {
            "session_id": session_id,
            "workspace": workspace_dir,
            "directory": workspace_dir,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_json(workspace / "opencode/session.json", session_meta)
        time.sleep(0.5)
        return session_id
    except Exception as exc:
        with (workspace / "opencode/errors.jsonl").open("a", encoding="utf-8") as error_file:
            error_file.write(json.dumps({"error": str(exc), "at": datetime.now(timezone.utc).isoformat()}) + "\n")
        logger.warning("Investigation OpenCode invocation failed: %s", exc)
        return None


def send_session_prompt(session_id: str, prompt_text: str, workspace: Optional[Path] = None) -> bool:
    """Sends prompt asynchronously to an existing OpenCode session using the active model."""
    try:
        model_id = OPENCODE_MODEL.split("/", 1)[-1] if "/" in OPENCODE_MODEL else OPENCODE_MODEL
        payload = {
            "parts": [{"type": "text", "text": prompt_text}],
            "model": {
                "providerID": "opencode",
                "modelID": model_id,
            },
        }
        url = f"{OPENCODE_BASE_URL}/session/{session_id}/prompt_async"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 202, 204)
    except Exception as exc:
        logger.warning(f"OpenCode prompt failed: {exc}")
        return False


def wait_for_opencode_file(
    file_path: Union[str, Path],
    session_id: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    max_timeout_sec: Optional[int] = None,
    poll_interval: float = 2.0,
    turn_name: str = "OpenCode task",
) -> Optional[Dict[str, Any]]:
    """Wait for an OpenCode-generated JSON file using active session-status listening.

    Monitors file availability and live session state (busy vs idle). If OpenCode
    is actively processing, it extends the wait dynamically rather than abruptly aborting.
    Returns the parsed JSON dict on success, or None on failure/timeout.
    """
    target = Path(file_path)
    base_timeout = max_timeout_sec if max_timeout_sec is not None else (timeout_seconds if timeout_seconds is not None else 60)
    start_time = time.monotonic()
    deadline = start_time + base_timeout
    hard_ceiling = start_time + max(base_timeout * 3, 300)
    logger.info(f"[{turn_name}] Waiting up to {base_timeout}s (hard ceiling {int(hard_ceiling - start_time)}s) for {target.name}...")

    was_busy = False
    status_url = f"{OPENCODE_BASE_URL}/session/status"

    while time.monotonic() < deadline:
        if target.exists() and target.stat().st_size > 0:
            elapsed = round(time.monotonic() - start_time, 2)
            try:
                with open(target, "r", encoding="utf-8") as f:
                    data = json.load(f)
                logger.info(f"[{turn_name}] File {target.name} generated successfully in {elapsed}s.")
                return data
            except json.JSONDecodeError as exc:
                logger.warning(f"[{turn_name}] Invalid JSON in {target.name} after {elapsed}s: {exc}")
            except Exception as exc:
                logger.warning(f"[{turn_name}] Error reading {target.name} after {elapsed}s: {exc}")

        # Active listener: inspect live OpenCode daemon session status
        if session_id:
            try:
                req = urllib.request.Request(status_url, headers={"User-Agent": "Jane-Bridge/1.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    statuses = json.loads(resp.read().decode("utf-8"))
                s_info = statuses.get(session_id)
                is_busy = isinstance(s_info, dict) and s_info.get("type") == "busy"
                if is_busy:
                    was_busy = True
                    # If nearing current deadline but OpenCode is still actively working, dynamically extend!
                    if time.monotonic() > deadline - 6 and deadline < hard_ceiling:
                        deadline = min(deadline + 20, hard_ceiling)
                        logger.info(f"[{turn_name}] OpenCode session {session_id} is still actively processing; extending deadline...")
                elif was_busy and not is_busy:
                    # Session finished its turn! Allow disk flush and check one final time
                    time.sleep(1.5)
                    if target.exists() and target.stat().st_size > 0:
                        try:
                            with open(target, "r", encoding="utf-8") as f:
                                data = json.load(f)
                            logger.info(f"[{turn_name}] File {target.name} completed as session became idle.")
                            return data
                        except Exception:
                            pass
                    logger.info(f"[{turn_name}] OpenCode session {session_id} finished (idle).")
                    break
            except Exception:
                pass

        time.sleep(poll_interval)

    elapsed = round(time.monotonic() - start_time, 2)
    if not target.exists():
        logger.warning(
            f"[{turn_name}] Timed out after {elapsed}s (limit {base_timeout}s). File {target} was never created."
        )
    else:
        logger.warning(
            f"[{turn_name}] Timed out after {elapsed}s (limit {base_timeout}s). File {target} exists ({target.stat().st_size} bytes) but is invalid or empty."
        )
    return None


def wait_for_investigation_report(inv_dir, timeout_seconds: int = 60) -> Optional[Dict[str, Any]]:
    """Poll for opencode/attribution_report.json in the investigation workspace."""
    path = Path(inv_dir) / "opencode" / "attribution_report.json"
    return wait_for_opencode_file(path, timeout_seconds=timeout_seconds)


def start_investigation_fanout(workspace: Path, query: str, fanout_count: int, session_id: Optional[str] = None) -> bool:
    """Turn 1: Request fanout queries from OpenCode session."""
    session_id = session_id or create_investigation_session(workspace)
    if not session_id:
        return False
    return send_session_prompt(session_id, _fanout_instruction(workspace, query, fanout_count), workspace=workspace)


def start_investigation_analysis(workspace: Path, session_id: Optional[str] = None) -> bool:
    """Turn 2: Request evidence analysis from OpenCode session."""
    session_id = session_id or create_investigation_session(workspace)
    if not session_id:
        return False
    return send_session_prompt(session_id, _evidence_instruction(workspace), workspace=workspace)


def start_osint_extraction(workspace: Path, session_id: Optional[str] = None) -> bool:
    """Turn 2.5: Request OSINT identity extraction from OpenCode session."""
    session_id = session_id or create_investigation_session(workspace)
    if not session_id:
        return False
    return send_session_prompt(session_id, _osint_instruction(workspace), workspace=workspace)


def start_graph_synthesis(workspace: Path, session_id: Optional[str] = None) -> bool:
    """Turn 3: Request threat intelligence graph extraction from OpenCode session.

    OpenCode outputs ONLY a structured JSON object to graph/threat_graph.json.
    It must NOT produce Cytoscape config, code, or prose. Our fixed renderer
    in frontend/graph/[id]/page.tsx consumes threat_graph.json via the DB.
    """
    session_id = session_id or create_investigation_session(workspace)
    if not session_id:
        return False
    return send_session_prompt(session_id, _graph_instruction(workspace), workspace=workspace)


def start_mermaid_enrichment(workspace: Path, session_id: Optional[str] = None) -> bool:
    """Turn 3.5: Request executive Mermaid diagram enrichment from OpenCode session."""
    session_id = session_id or create_investigation_session(workspace)
    if not session_id:
        return False
    return send_session_prompt(session_id, _mermaid_instruction(workspace), workspace=workspace)


def wait_for_mermaid_file(
    file_path: Union[str, Path],
    session_id: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    poll_interval: float = 2.0,
    turn_name: str = "Turn 3.5: Mermaid Enrichment",
) -> Optional[str]:
    """Wait for OpenCode to generate graph/mermaid.mmd and validate its syntax.

    Returns the validated, clean Mermaid string on success, or None on failure/timeout.
    """
    target = Path(file_path)
    base_timeout = timeout_seconds if timeout_seconds is not None else TIMEOUT_TURN35_MERMAID
    start_time = time.monotonic()
    deadline = start_time + base_timeout
    hard_ceiling = start_time + max(base_timeout * 3, 240)
    logger.info(f"[{turn_name}] Waiting up to {base_timeout}s for {target.name}...")

    was_busy = False
    status_url = f"{OPENCODE_BASE_URL}/session/status"

    while time.monotonic() < deadline:
        if target.exists() and target.stat().st_size > 0:
            elapsed = round(time.monotonic() - start_time, 2)
            try:
                raw_text = target.read_text(encoding="utf-8")
                cleaned = raw_text.strip()
                if cleaned.startswith("```"):
                    lines = [ln for ln in cleaned.splitlines() if not ln.strip().startswith("```")]
                    cleaned = "\n".join(lines).strip()
                if validate_mermaid_syntax(cleaned):
                    if cleaned != raw_text:
                        target.write_text(cleaned, encoding="utf-8")
                    logger.info(f"[{turn_name}] Valid Mermaid diagram generated in {elapsed}s.")
                    return cleaned
                else:
                    logger.warning(f"[{turn_name}] Mermaid file exists but failed syntax validation after {elapsed}s.")
            except Exception as exc:
                logger.warning(f"[{turn_name}] Error reading {target.name} after {elapsed}s: {exc}")

        # Active listener: inspect live OpenCode daemon session status
        if session_id:
            try:
                req = urllib.request.Request(status_url, headers={"User-Agent": "Jane-Bridge/1.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    statuses = json.loads(resp.read().decode("utf-8"))
                s_info = statuses.get(session_id)
                is_busy = isinstance(s_info, dict) and s_info.get("type") == "busy"
                if is_busy:
                    was_busy = True
                    if time.monotonic() > deadline - 6 and deadline < hard_ceiling:
                        deadline = min(deadline + 15, hard_ceiling)
                        logger.info(f"[{turn_name}] OpenCode still generating Mermaid diagram; extending deadline...")
                elif was_busy and not is_busy:
                    time.sleep(1.0)
                    if target.exists() and target.stat().st_size > 0:
                        try:
                            raw_text = target.read_text(encoding="utf-8")
                            cleaned = raw_text.strip()
                            if cleaned.startswith("```"):
                                lines = [ln for ln in cleaned.splitlines() if not ln.strip().startswith("```")]
                                cleaned = "\n".join(lines).strip()
                            if validate_mermaid_syntax(cleaned):
                                if cleaned != raw_text:
                                    target.write_text(cleaned, encoding="utf-8")
                                return cleaned
                        except Exception:
                            pass
                    break
            except Exception:
                pass

        time.sleep(poll_interval)

    elapsed = round(time.monotonic() - start_time, 2)
    logger.warning(f"[{turn_name}] Timed out or completed without valid Mermaid diagram after {elapsed}s.")
    return None


# ---------------------------------------------------------------------------
# Fallback: build a minimal empty graph structure when OpenCode is unavailable
# ---------------------------------------------------------------------------

def build_concentric_cytoscape_fallback(
    inv_id: str,
    extracted_data: Dict[str, Any],
    locksmith_data: Dict[str, Any],
    stylometry_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Returns an empty canonical Cytoscape elements structure as fallback.

    Under the new data-flow, Turn 3's threat_graph.json is the only source
    of graph nodes/edges. This fallback returns empty elements so the renderer
    shows a blank canvas rather than fabricated nodes.
    """
    return {"elements": {"nodes": [], "edges": []}}


# ---------------------------------------------------------------------------
# Legacy target workspace (per-URL, pre-investigation-workspace era)
# Retained for backward compatibility with older callers only.
# ---------------------------------------------------------------------------

def create_target_workspace(
    target_url: str,
    raw_html: str,
    heuristics: Dict[str, Any],
    workspaces_dir: Optional[Path] = None,
) -> Path:
    """
    Creates an isolated folder for this specific onion target so OpenCode
    never gets confused by other files or the root repository.
    """
    root = workspaces_dir or (Path(__file__).resolve().parent.parent / "data" / "workspaces")
    url_hash = hashlib.sha256(target_url.encode("utf-8")).hexdigest()[:12]
    target_dir = root / f"target_{url_hash}"
    target_dir.mkdir(parents=True, exist_ok=True)

    (target_dir / "target_page.html").write_text(raw_html or "<html><body>No HTML</body></html>", encoding="utf-8")
    (target_dir / "heuristics.json").write_text(json.dumps(heuristics, indent=2), encoding="utf-8")

    instruction = f"""# NTRO Dark Web Threat Actor Attribution Directive

TARGET ONION: {target_url}

You are an authorized Senior Intelligence Analyst at the National Technical Research Organisation (NTRO).
Your mission is to perform automated threat actor profiling and evidence extraction on this captured dark web hidden service.

## INSTRUCTIONS:
1. Examine `target_page.html` and `heuristics.json` in this workspace.
2. Identify:
   - Marketplace / Forum Brand Name
   - Primary Threat Actors / Operators / Vendor Handles
   - Illicit Commodities or Services Sold (e.g. Carding, CVV Dumps, Narcotics, Escrow, Malware)
   - Crypto Wallets & Messaging Channels
3. CRITICAL EVIDENCE & ABSTENTION REQUIREMENT:
   - For EVERY entity or actor identified, you MUST cite the EXACT VERBATIM QUOTE from `target_page.html` as evidence.
   - If the page is a legitimate search engine (like Ahmia), index, forum without illicit commerce, or personal blog, you MUST set:
     `"threat_category": "INSUFFICIENT_EVIDENCE"`
     and leave `"threat_actors": []` and `"commodities": []`. Never guess or hallucinate actors if verbatim proof does not exist.
4. Output your analysis into `attribution_report.json` matching the exact JSON format below:

```json
{{
  "marketplace_name": "Extracted Name",
  "threat_category": "Financial Fraud / Carding | Narcotics | Cybercrime | Counterfeiting | INSUFFICIENT_EVIDENCE",
  "threat_actors": [
    {{
      "designated_id": "TA-SUSPECT-1",
      "primary_handle": "vendor_alias",
      "role": "Vendor / Escrow / Admin",
      "evidence_quote": "Exact verbatim sentence from target_page.html mentioning this actor"
    }}
  ],
  "commodities": [
    {{
      "name": "Stolen Credit Card Dumps",
      "category": "Carding",
      "evidence_quote": "Exact verbatim text quote offering this commodity"
    }}
  ],
  "graph_links": [
    {{
      "source": "vendor_alias",
      "target": "Extracted Name",
      "relation": "OPERATES",
      "confidence": 0.95,
      "evidence_quote": "Exact quote"
    }}
  ],
  "stylometric_notes": "Linguistic quirks, active hours, or distinct phrasing patterns."
}}
```
"""
    (target_dir / "instruction.md").write_text(instruction, encoding="utf-8")
    return target_dir


def create_job_workspace(
    job_id: str,
    pages: List[Dict[str, Any]],
    heuristics: Dict[str, Any],
    chunks: Optional[List[Dict[str, Any]]] = None,
    workspaces_dir: Optional[Path] = None,
) -> Path:
    """
    Creates an aggregated workspace containing ALL scraped site HTML files,
    manifest, evidence chunks, and strict agents.md format instructions.
    """
    root = workspaces_dir or (Path(__file__).resolve().parent.parent / "data" / "workspaces")
    job_dir = root / f"job_{job_id}"
    pages_dir = job_dir / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)

    manifest_entries = []
    for idx, page in enumerate(pages, 1):
        url = page.get("url", "")
        host = page.get("onion_address", "") or hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
        clean_host = re.sub(r'[^a-zA-Z0-9_]', '_', host)[:24]
        filename = f"page_{idx:02d}_{clean_host}.html"
        raw_html = page.get("raw_html", "") or "<html><body>No HTML content</body></html>"
        (pages_dir / filename).write_text(raw_html, encoding="utf-8")

        manifest_entries.append({
            "target_url": url,
            "onion_address": page.get("onion_address", ""),
            "title": page.get("title", ""),
            "html_path": f"pages/{filename}",
            "byte_size": len(raw_html),
        })

    (job_dir / "manifest.json").write_text(json.dumps(manifest_entries, indent=2), encoding="utf-8")
    (job_dir / "evidence_chunks.json").write_text(json.dumps(chunks or [], indent=2), encoding="utf-8")
    (job_dir / "heuristics.json").write_text(json.dumps(heuristics, indent=2), encoding="utf-8")

    agents_directive = f"""# NTRO Multi-Site Threat Actor Investigation & Attribution Directive

INVESTIGATION JOB ID: {job_id}

You are an authorized Senior Intelligence Officer at the National Technical Research Organisation (NTRO).
Your mission is to perform automated threat actor profiling across ALL captured hidden services in this workspace.

## WORKSPACE RESOURCES:
- `manifest.json`: Index of all {len(pages)} captured hidden services with local HTML paths.
- `pages/`: Full raw captured HTML for each onion site.
- `evidence_chunks.json`: Pre-sliced traceable text chunks with SHA-256 hashes.
- `heuristics.json`: Regex IOCs, Locksmith server banners, and Shodan findings.

## MANDATORY EXTRACTION CRITERIA:
Examine all pages and evidence chunks. Identify and extract:
1. **ORGANISATION**: Marketplaces, syndicates, groups, forums (e.g. "UniMkts", "Hydra Syndicate").
2. **ACCOUNT / ALIAS**: Human vendor personas, operator handles, admin names (e.g. "Vendor_Alpha").
3. **COMMODITIES & SERVICES**: Specific illicit wares (e.g. "Credit card dumps", "Stealth escrow", "Malware").
4. **ACTIONS & RELATIONSHIPS**:
   - `OFFERS` / `SELLS` (Actor or Org -> Commodity)
   - `CONTROLS` / `OPERATES` (Actor -> Org)
   - `CONTACTS` (Actor -> Comms Handle)
   - `USES_CRYPTO_ADDRESS` (Actor -> Bitcoin / Monero Address)
   - `USES_PGP_KEY` (Actor -> PGP Key)
5. **TECHNICAL IDENTIFIERS**: Wallets, PGP, Telegram, Session IDs, Emails.

## EVIDENCE & MERMAID SPECIFICATION:
1. For EVERY extracted entity and relationship, cite an EXACT VERBATIM QUOTE from the source HTML or chunk.
2. In addition to the entities, produce a clean, syntax-safe Mermaid graph string (`mermaid_graph`) connecting all nodes.

Output your final analysis into `attribution_report.json` matching this exact schema:
```json
{{
  "job_id": "{job_id}",
  "threat_category": "Financial Fraud / Carding | Narcotics | Cybercrime | Counterfeiting | INSUFFICIENT_EVIDENCE",
  "organisations": [
    {{
      "name": "Market Name",
      "type": "ORGANISATION",
      "evidence_quote": "Verbatim quote naming this organization"
    }}
  ],
  "threat_actors": [
    {{
      "designated_id": "TA-SUSPECT-1",
      "primary_handle": "vendor_alias",
      "role": "Vendor / Admin",
      "evidence_quote": "Verbatim quote mentioning this actor"
    }}
  ],
  "commodities": [
    {{
      "name": "Stolen Credit Card Dumps",
      "category": "Carding",
      "evidence_quote": "Verbatim text quote offering this commodity"
    }}
  ],
  "graph_links": [
    {{
      "source": "vendor_alias",
      "target": "Market Name",
      "relation": "OPERATES",
      "confidence": 0.95,
      "evidence_quote": "Verbatim quote linking them"
    }}
  ],
  "mermaid_graph": "graph LR\\n  actor[\\"Actor: vendor_alias\\"] -->|OPERATES| org[\\"Org: Market Name\\"]"
}}
```
"""
    (job_dir / "agents.md").write_text(agents_directive, encoding="utf-8")
    (job_dir / "instruction.md").write_text(agents_directive, encoding="utf-8")
    return job_dir


def is_opencode_available() -> bool:
    try:
        req = urllib.request.Request(f"{OPENCODE_BASE_URL}/global/health", headers={"User-Agent": "Jane-Bridge/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def start_opencode_analysis(target_dir: Path) -> Optional[str]:
    """Start OpenCode analysis without holding the caller's HTTP request open."""
    try:
        create_req = urllib.request.Request(
            f"{OPENCODE_BASE_URL}/session",
            data=json.dumps({"title": f"Jane Attribution - {target_dir.name}"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(create_req, timeout=5) as resp:
            sdata = json.loads(resp.read().decode("utf-8"))
            session_id = sdata.get("id")

        if not session_id:
            return None

        session_meta = {
            "session_id": session_id,
            "target_dir": str(target_dir),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "url": f"{OPENCODE_BASE_URL}/session/{session_id}",
        }
        (target_dir / "opencode_session.json").write_text(json.dumps(session_meta, indent=2), encoding="utf-8")

        directive_file = target_dir / "agents.md" if (target_dir / "agents.md").exists() else target_dir / "instruction.md"
        instruction_text = directive_file.read_text(encoding="utf-8")
        async_payload = {
            "parts": [
                {
                    "type": "text",
                    "text": f"Please analyze files in workspace `{target_dir}` as instructed:\n\n{instruction_text}"
                }
            ]
        }
        async_req = urllib.request.Request(
            f"{OPENCODE_BASE_URL}/session/{session_id}/prompt_async",
            data=json.dumps(async_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(async_req, timeout=10) as resp:
            if resp.status not in (200, 202, 204):
                raise RuntimeError(f"OpenCode async prompt returned HTTP {resp.status}")
        return session_id

    except Exception as e:
        logger.warning(f"OpenCode API invocation failed: {e}")
    return None


def wait_for_opencode_report(
    target_dir: Path,
    session_id: str,
    max_timeout_sec: int = 30,
    report_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Wait for OpenCode report with fast detection and safety timeout."""
    status_url = f"{OPENCODE_BASE_URL}/session/status"
    start_time = time.monotonic()
    report_file = report_path or (target_dir / "attribution_report.json")

    while (time.monotonic() - start_time) < max_timeout_sec:
        if report_file.exists() and report_file.stat().st_size > 100:
            try:
                return json.loads(report_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        try:
            req = urllib.request.Request(status_url, headers={"User-Agent": "Jane-Bridge/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                statuses = json.loads(resp.read().decode("utf-8"))
            status = statuses.get(session_id)
            if status is None and report_file.exists():
                return json.loads(report_file.read_text(encoding="utf-8"))
            state = status.get("type") if isinstance(status, dict) else status
            if state == "idle":
                if report_file.exists():
                    return json.loads(report_file.read_text(encoding="utf-8"))
                raise RuntimeError("OpenCode became idle without attribution_report.json")
        except urllib.error.URLError:
            pass
        time.sleep(1.5)

    if report_file.exists():
        return json.loads(report_file.read_text(encoding="utf-8"))
    raise TimeoutError(f"OpenCode analysis timed out after {max_timeout_sec}s")


def validate_quote_grounding(report: Dict[str, Any], raw_html: str) -> Dict[str, Any]:
    """
    Verifies that every evidence quote in the attribution report actually exists
    verbatim in the target HTML. Flags hallucinations and marks grounded status.
    """
    if not raw_html or not isinstance(report, dict):
        return report

    def _normalize(s: str) -> str:
        return " ".join(re.sub(r'[^a-zA-Z0-9\s]', ' ', s.lower()).split())

    norm_html = _normalize(raw_html)

    for actor in report.get("threat_actors", []):
        quote = actor.get("evidence_quote", "")
        if quote:
            norm_q = _normalize(quote)
            actor["grounded"] = (norm_q in norm_html) if len(norm_q) > 10 else True
        else:
            actor["grounded"] = False

    for comm in report.get("commodities", []):
        quote = comm.get("evidence_quote", "")
        if quote:
            norm_q = _normalize(quote)
            comm["grounded"] = (norm_q in norm_html) if len(norm_q) > 10 else True
        else:
            comm["grounded"] = False

    for link in report.get("graph_links", []):
        quote = link.get("evidence_quote", "")
        if quote:
            norm_q = _normalize(quote)
            link["grounded"] = (norm_q in norm_html) if len(norm_q) > 10 else True
        else:
            link["grounded"] = False

    return report


def generate_forensic_profile(target_dir: Path, target_url: str) -> Dict[str, Any]:
    """Run mandatory OpenCode attribution and return its JSON report."""
    if not is_opencode_available():
        raise RuntimeError("OpenCode daemon unavailable; AI analysis is required")

    logger.info(f"[*] OpenCode Daemon online at {OPENCODE_BASE_URL} -> Running AI analysis")
    session_id = start_opencode_analysis(target_dir)
    if not session_id:
        raise RuntimeError("OpenCode analysis could not be started")
    report = wait_for_opencode_report(target_dir, session_id)
    report["opencode_session_id"] = session_id

    html_file = target_dir / "target_page.html"
    if html_file.exists():
        raw_html = html_file.read_text(encoding="utf-8", errors="ignore")
        report = validate_quote_grounding(report, raw_html)

    return report


def _legacy_fallback_profile(target_dir: Path, target_url: str) -> Dict[str, Any]:
    """Fallback profile when OpenCode is unavailable: returns NO fabricated actors."""
    raw_html = (target_dir / "target_page.html").read_text(encoding="utf-8")
    heuristics_file = target_dir / "heuristics.json"
    heuristics = json.loads(heuristics_file.read_text(encoding="utf-8")) if heuristics_file.exists() else {}

    m_name = "Hidden Service Marketplace"
    title_match = re.search(r'<title>(.*?)</title>', raw_html, re.IGNORECASE)
    if title_match:
        m_name = title_match.group(1).split("-")[0].strip()

    report = {
        "marketplace_name": m_name,
        "threat_category": "INSUFFICIENT_EVIDENCE",
        "threat_actors": [],
        "commodities": [],
        "graph_links": [],
        "stylometric_notes": "AI analysis unavailable; no actors or commodities fabricated.",
    }

    (target_dir / "attribution_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def run_ai(
    batch_data: Dict[str, Any],
    extracted_data: Optional[Dict[str, Any]] = None,
    locksmith_data: Optional[Dict[str, Any]] = None,
    profiler_fn: Optional[Any] = None,
) -> Dict[str, Any]:
    """Microservice entrypoint: Executes AI reasoning via OpenCode for each page in batch."""
    pages = batch_data.get("pages", [])
    reports = []
    _profiler = profiler_fn or generate_forensic_profile

    entities_by_url = {}
    if extracted_data:
        for r in extracted_data.get("results_by_page", []):
            entities_by_url[r.get("url", "")] = r.get("entities", [])

    for page in pages:
        url = page.get("url", "")
        raw_html = page.get("raw_html", "")
        heuristics = {
            "title": page.get("title", ""),
            "onion_address": page.get("onion_address", ""),
            "response_headers": page.get("response_headers", {}),
            "meta_tags": page.get("meta_tags", {}),
            "entities": entities_by_url.get(url, []),
        }

        target_dir = create_target_workspace(
            target_url=url,
            raw_html=raw_html,
            heuristics=heuristics,
        )

        try:
            report = _profiler(target_dir=target_dir, target_url=url)
        except Exception as e:
            logger.warning(f"OpenCode run failed ({e}), using analytical profile fallback")
            report = _legacy_fallback_profile(target_dir=target_dir, target_url=url)

        reports.append({
            "url": url,
            "onion_address": page.get("onion_address", ""),
            "report": report,
        })

    return {
        "status": "AI_SYNTHESIZED",
        "batch_id": batch_data.get("batch_id", ""),
        "reports_count": len(reports),
        "reports": reports,
    }



# ---------------------------------------------------------------------------
# SQL Studio: OpenCode Session & Natural Language to SQL
# ---------------------------------------------------------------------------

def create_sql_opencode_session(session_id: str, schema_metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Creates a persistent OpenCode session specifically scoped to the SQL Studio workspace."""
    try:
        if not is_opencode_available():
            return None
        # Provision dedicated data/sql_studio workspace with opencode.json & AGENTS.md
        ensure_sql_studio_harness(schema_metadata=schema_metadata)
        create_req = urllib.request.Request(
            f"{OPENCODE_BASE_URL}/session",
            data=json.dumps({
                "title": f"Jane SQL Studio - {session_id}",
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(create_req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("id")
    except Exception as exc:
        logger.warning(f"Failed to create OpenCode SQL session: {exc}")
        return None


def _format_schema_for_llm(schema_metadata: Optional[Dict[str, Any]] = None) -> str:
    if not schema_metadata or "tables" not in schema_metadata:
        return "Tables: threat_actors, identifiers, onion_pages, graph_nodes, graph_edges, investigations, ip_enrichment, evidence_chunks, search_hits"
    lines = []
    for t in schema_metadata["tables"]:
        tname = t["table_name"]
        cols = ", ".join(f"{c['name']} ({c['type']})" for c in t.get("columns", []))
        lines.append(f"- {tname} [{t.get('row_count', 0)} rows]: {cols}")
    return "\n".join(lines)


def _synthesize_sqlite_query(prompt: str, schema_metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Deterministic, schema-aware SQL generator for Jane's 12 threat intelligence tables."""
    p_lower = prompt.lower().strip()

    # Default fallback
    sql = "SELECT id, designated_id, primary_handle, threat_category, confidence FROM threat_actors ORDER BY confidence DESC LIMIT 20;"
    explanation = "Querying top threat actors sorted by attribution confidence."

    # Threat Actors
    if any(k in p_lower for k in ("actor", "threat actor", "suspect", "persona", "vendor", "handle")):
        where_clauses = []
        if "high confidence" in p_lower or ">= 0.8" in p_lower or "confidence > 0.8" in p_lower:
            where_clauses.append("confidence >= 0.8")
        elif "confidence" in p_lower and "0." in p_lower:
            m = re.search(r'0\.\d+', p_lower)
            if m:
                where_clauses.append(f"confidence >= {m.group(0)}")
        if "carding" in p_lower:
            where_clauses.append("threat_category LIKE '%Carding%'")
        elif "narcotics" in p_lower or "drug" in p_lower:
            where_clauses.append("threat_category LIKE '%Narcotics%'")
        elif "fraud" in p_lower:
            where_clauses.append("threat_category LIKE '%Fraud%'")

        where_str = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        sql = f"SELECT id, designated_id, primary_handle, threat_category, confidence, attributed_onions FROM threat_actors{where_str} ORDER BY confidence DESC LIMIT 50;"
        explanation = f"Locating threat actor profiles matching criteria with confidence scores."

    # Identifiers / Wallets / PGP / Handles
    elif any(k in p_lower for k in ("wallet", "crypto", "bitcoin", "btc", "monero", "xmr", "pgp", "sanction", "telegram", "email", "identifier", "ioc")):
        where_clauses = []
        if "sanction" in p_lower:
            where_clauses.append("is_sanctioned = 1")
        if any(c in p_lower for c in ("bitcoin", "btc")):
            where_clauses.append("type = 'BITCOIN_ADDRESS'")
        elif any(c in p_lower for c in ("monero", "xmr")):
            where_clauses.append("type = 'MONERO_ADDRESS'")
        elif "pgp" in p_lower:
            where_clauses.append("type = 'PGP_KEY'")
        elif "telegram" in p_lower:
            where_clauses.append("type = 'TELEGRAM_HANDLE'")
        elif "email" in p_lower:
            where_clauses.append("type = 'EMAIL'")

        where_str = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        sql = f"SELECT id, type, value, confidence, is_sanctioned, evidence_quote, first_seen, last_seen FROM identifiers{where_str} ORDER BY occurrence_count DESC, confidence DESC LIMIT 50;"
        explanation = "Querying extracted IOC identifiers and cryptographic wallet assets."

    # Leaked Infrastructure / Locksmith / Origin IPs
    elif any(k in p_lower for k in ("leaked", "ip", "origin", "infrastructure", "locksmith", "shodan", "asn", "country", "hosting", "vpn", "tor")):
        where_clauses = []
        if "vpn" in p_lower or "proxy" in p_lower:
            where_clauses.append("proxy_or_vpn = 1")
        if "hosting" in p_lower:
            where_clauses.append("hosting = 1")
        if "tor" in p_lower:
            where_clauses.append("tor = 1")

        where_str = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        sql = f"SELECT ip_address, country_name, city, asn, organization, isp, proxy_or_vpn, tor, enriched_at FROM ip_enrichment{where_str} ORDER BY enriched_at DESC LIMIT 50;"
        explanation = "Inspecting corroborated clearweb origin IP addresses and network registrations."

    # Onion Pages / Crawled HTML
    elif any(k in p_lower for k in ("page", "onion", "crawl", "dark web", "hidden service", "title", "banner", "favicon")):
        where_clauses = []
        if "banner" in p_lower:
            where_clauses.append("server_banner IS NOT NULL AND server_banner != ''")
        if "favicon" in p_lower or "mmh3" in p_lower:
            where_clauses.append("favicon_mmh3 IS NOT NULL AND favicon_mmh3 != ''")

        where_str = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        sql = f"SELECT id, url, title, server_banner, favicon_mmh3, etag, created_at FROM onion_pages{where_str} ORDER BY created_at DESC LIMIT 50;"
        explanation = "Retrieving preserved dark web onion pages and infrastructure headers."

    # Graph Relationships (Nodes / Edges)
    elif any(k in p_lower for k in ("graph", "edge", "relationship", "connection", "link", "operates", "sells", "trust")):
        if "node" in p_lower or "product" in p_lower or "marketplace" in p_lower:
            sql = "SELECT id, label, node_type, community, degree FROM graph_nodes ORDER BY degree DESC LIMIT 50;"
            explanation = "Listing authoritative graph nodes ranked by connectivity degree."
        else:
            where_clauses = []
            if "operates" in p_lower:
                where_clauses.append("edge_type = 'OPERATES_ON'")
            elif "sells" in p_lower:
                where_clauses.append("edge_type = 'SELLS'")
            elif "trust" in p_lower:
                where_clauses.append("edge_type = 'TRUST'")

            where_str = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
            sql = f"SELECT source, target, edge_type, confidence, evidence_quote FROM graph_edges{where_str} ORDER BY confidence DESC LIMIT 50;"
            explanation = "Fetching verified threat graph relationship edges."

    # Investigations / Overview / Counts
    elif any(k in p_lower for k in ("investigation", "case", "hunt", "recent", "run", "status")):
        if "count" in p_lower or "summary" in p_lower:
            sql = "SELECT status, COUNT(*) as count, SUM(page_count) as total_pages FROM investigations GROUP BY status;"
            explanation = "Aggregating investigation runs grouped by operational status."
        else:
            sql = "SELECT id, query, status, page_count, created_at, updated_at FROM investigations ORDER BY created_at DESC LIMIT 20;"
            explanation = "Listing recent investigation hunt operations."

    # Aggregations / Top counts
    elif "count" in p_lower or "how many" in p_lower:
        if "actor" in p_lower:
            sql = "SELECT threat_category, COUNT(*) as count FROM threat_actors GROUP BY threat_category ORDER BY count DESC;"
            explanation = "Counting threat actors grouped by threat category."
        elif "identifier" in p_lower or "ioc" in p_lower:
            sql = "SELECT type, COUNT(*) as count FROM identifiers GROUP BY type ORDER BY count DESC;"
            explanation = "Counting extracted identifiers by category."
        else:
            sql = "SELECT 'threat_actors' as entity, COUNT(*) as count FROM threat_actors UNION ALL SELECT 'onion_pages', COUNT(*) FROM onion_pages UNION ALL SELECT 'identifiers', COUNT(*) FROM identifiers;"
            explanation = "Counting primary threat intelligence records across core tables."

    return {
        "sql": sql,
        "explanation": explanation,
        "source": "synthesizer",
    }


def inject_sql_studio_prompt(user_query: str, schema_metadata: Optional[Dict[str, Any]] = None) -> str:
    """
    Transforms the raw user query into an improved, agentic prompt for OpenCode.
    Compulsorily mandates following AGENTS.md, adheres to read-only SQLite dialect rules,
    and contextualizes the real user query.
    """
    clean_query = user_query.strip()
    schema_txt = _format_schema_for_llm(schema_metadata)

    return f"""You are Jane's SQLite SQL agent. Follow `data/sql_studio/AGENTS.md` as the authoritative schema, safety, and behavior specification.

For the user's request:

* Write the simplest safe SQL that directly answers it.
* Execute the query and return the actual result.
* Use only `SELECT` or `WITH ... SELECT`; never modify database state.
* Never use `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `ATTACH`, `DETACH`, `PRAGMA`, or equivalent mutation/administrative statements.
* Use case-insensitive matching for text searches when appropriate.
* Use `LIMIT 50` by default for row results unless the user specifies another reasonable limit or the query is an aggregation.
* Stay strictly within the user's requested scope; add only small, directly relevant context.
* Show the executed SQL and its result. Never fabricate execution or results.

Schema context:
{schema_txt}

User request:
{clean_query}
"""


def generate_sql_with_ai(
    prompt: str,
    schema_metadata: Optional[Dict[str, Any]] = None,
    opencode_session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Translates a natural language question into a safe SQLite query using the live OpenCode AI daemon.
    Synchronously queries POST /session/{id}/message to obtain genuine LLM-synthesized SQL.
    Injects an improved prompt compelling OpenCode to act as Jane's SQL agent and read AGENTS.md.
    """
    clean_prompt = prompt.strip()
    if not clean_prompt:
        return {
            "sql": "SELECT * FROM threat_actors LIMIT 10;",
            "explanation": "Default query for threat actors.",
            "source": "fallback",
        }

    improved_prompt = inject_sql_studio_prompt(clean_prompt, schema_metadata=schema_metadata)

    # Attempt OpenCode live session if daemon is reachable
    if is_opencode_available():
        sid = opencode_session_id or create_sql_opencode_session("Interactive Studio", schema_metadata=schema_metadata)
        if sid:
            try:
                msg_payload = {"parts": [{"type": "text", "text": improved_prompt}]}
                req = urllib.request.Request(
                    f"{OPENCODE_BASE_URL}/session/{sid}/message",
                    data=json.dumps(msg_payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=20) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))

                # Collect text parts emitted by OpenCode's LLM
                text_accum = []
                for part in resp_data.get("parts", []):
                    if part.get("type") == "text" and "text" in part:
                        text_accum.append(part["text"])
                full_text = "\n".join(text_accum).strip()

                # Extract SQL from markdown code block
                sql_match = re.search(r"```(?:sql)?\s*([\s\S]*?)\s*```", full_text, re.IGNORECASE)
                if sql_match:
                    sql_candidate = sql_match.group(1).strip()
                    explanation = re.sub(r"```(?:sql)?\s*[\s\S]*?\s*```", "", full_text).strip()
                else:
                    raw_sql_match = re.search(r"((?:SELECT|WITH)\b[\s\S]+?;?)", full_text, re.IGNORECASE)
                    if raw_sql_match:
                        sql_candidate = raw_sql_match.group(1).strip()
                        explanation = re.sub(r"(?:SELECT|WITH)\b[\s\S]+?;?", "", full_text, flags=re.IGNORECASE).strip()
                    else:
                        sql_candidate = None
                        explanation = full_text

                if sql_candidate:
                    if not sql_candidate.endswith(";"):
                        sql_candidate += ";"
                    logger.info("OpenCode generated SQL successfully for query: %s", clean_prompt[:50])
                    return {
                        "sql": sql_candidate,
                        "explanation": explanation or "Generated query matching your criteria.",
                        "source": "opencode",
                        "opencode_session_id": sid,
                        "injected_prompt": improved_prompt,
                    }
                else:
                    logger.warning("OpenCode responded without SQL block: %s", full_text[:100])
            except Exception as exc:
                logger.warning("OpenCode /message failed (%s), falling back to schema synthesizer", exc)

    # Fallback to local schema-aware synthesizer ONLY if OpenCode is unreachable or unparseable
    fallback_res = _synthesize_sqlite_query(clean_prompt, schema_metadata)
    fallback_res["source"] = "synthesizer_fallback"
    fallback_res["injected_prompt"] = improved_prompt
    return fallback_res


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Jane AI Layer: OpenCode Bridge & Forensic Profiler")
    parser.add_argument("--batch", "-b", type=str, help="Path to Scout batch JSON file")
    args = parser.parse_args()

    if args.batch:
        batch_path = Path(args.batch)
        if not batch_path.exists():
            print(f"Error: {args.batch} not found")
            return
        with open(batch_path, "r", encoding="utf-8") as f:
            batch_data = json.load(f)
        result = run_ai(batch_data)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
