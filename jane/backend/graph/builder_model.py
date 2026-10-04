"""
graph/model.py — Pure data definitions for the VoidAccess graph layer.

No graph logic here — only node/edge type constants and dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Node type constants
# ---------------------------------------------------------------------------


class NODE_TYPES:
    THREAT_ACTOR = "ThreatActor"
    CRYPTO_WALLET = "CryptoWallet"
    ONION_URL = "OnionURL"
    FORUM = "Forum"
    MALWARE_FAMILY = "MalwareFamily"
    RANSOMWARE_GROUP = "RansomwareGroup"
    PGP_KEY = "PGPKey"
    EMAIL_ADDRESS = "EmailAddress"
    CVE = "CVE"
    PASTE = "Paste"
    IP_ADDRESS = "IPAddress"
    PHONE_NUMBER = "PhoneNumber"
    ORGANIZATION = "Organization"
    DOMAIN = "Domain"
    DATE = "Date"
    # Credential / token nodes — high-severity IOC.  All extracted
    # credential types (AWS / GitHub / Slack / Discord / JWT / Google /
    # Stripe / generic API key / stealer-log URL) map to this single
    # node type so the graph stays compact and queryable.
    CREDENTIAL = "Credential"
    # Messaging / identity handle nodes — communication IOCs.  All extracted
    # messaging types (Telegram / Discord / XMPP / Tox / Session / Matrix /
    # Wire / ICQ / Wickr) collapse to this single node type.  The original
    # subtype is preserved in node metadata (`messaging_kind`) so downstream
    # queries can still distinguish a Telegram handle from a Tox ID even
    # though they share a node type.  Visualized as purple in the graph
    # (see graph/visualize.py).
    MESSAGING_HANDLE = "MessagingHandle"
    # Network indicator nodes — IPv6 + MAC addresses.  These are
    # second-tier network IOCs (IP_ADDRESS is the more common v4 form
    # and reuses its own node type).  The original subtype is preserved
    # in node metadata (`network_kind`) so a query can filter by IPv6
    # vs MAC even though they share a node type.
    NETWORK_INDICATOR = "NetworkIndicator"
    # Malware indicator nodes — YARA rule names + Nuclei template IDs.
    # Both are detection artifacts used by security tooling; a YARA
    # rule name + the same vendor's Nuclei template should appear in
    # the same investigation cluster.  The original subtype is
    # preserved in node metadata (`malware_kind`).
    MALWARE_INDICATOR = "MalwareIndicator"
    # Content indicator nodes — content-addressed identifiers (IPFS
    # CIDs), credential combo-list block markers, and BIP39 seed
    # phrase detection markers.  The original subtype is preserved
    # in node metadata (`content_kind`).  All three signal "this
    # page contains a content artifact of value" but are
    # categorically different from credentials (which is a different
    # node type with its own collapse rules).
    CONTENT_INDICATOR = "ContentIndicator"


# ---------------------------------------------------------------------------
# Edge type constants
# ---------------------------------------------------------------------------


class EDGE_TYPES:
    CO_APPEARED_ON = "CO_APPEARED_ON"           # two entities on the same page
    POSTED_BY = "POSTED_BY"                     # content attributed to a handle
    LINKED_TO = "LINKED_TO"                     # URL links to URL
    MEMBER_OF = "MEMBER_OF"                     # handle to group/forum
    USES = "USES"                               # actor uses a malware family
    CLAIMED = "CLAIMED"                         # group claimed an attack
    LIKELY_SAME_ACTOR = "LIKELY_SAME_ACTOR"     # inferred, medium confidence
    CONFIRMED_SAME_ACTOR = "CONFIRMED_SAME_ACTOR"  # PGP key match, high confidence
    CO_INVESTIGATION = "CO_INVESTIGATION"       # Entities found in same investigation across multiple pages
    PAID_TO = "PAID_TO"                         # financial transaction
    FUNDED_BY = "FUNDED_BY"                     # financial transaction
    # Typed relationships from the LLM relationship-extraction pass.  These
    # sit ALONGSIDE CO_APPEARED_ON — they are emitted only when the LLM finds
    # genuine evidence for a specific relationship, and each carries its own
    # claim confidence (not the flat co-occurrence confidence).
    DROPS = "DROPS"                             # malware drops another payload
    CONTROLS = "CONTROLS"                       # actor controls a wallet / infra
    TARGETS = "TARGETS"                         # actor/campaign targeted an org
    EXPLOITS = "EXPLOITS"                       # malware/actor exploits a CVE
    COMMUNICATES_WITH = "COMMUNICATES_WITH"     # C2 / host communication


# ---------------------------------------------------------------------------
# Redesigned threat-actor relationship graph: canonical 4x4 vocabulary.
# ONLY these node/edge types may ever be inserted into graph_nodes/edges.
# Everything else (asset paths, banners, IPs, emails/phones, free text)
# stays in its evidence table and is never rendered as a graph node.
# ---------------------------------------------------------------------------


class CANONICAL_NODE_TYPES:
    ACTOR = "Actor"                        # threat actor / vendor / persona
    MARKETPLACE = "Marketplace"            # distinct .onion domain/site
    PRODUCT = "Product"                    # commodity, compound child of Actor
    SHARED_IDENTIFIER = "SharedIdentifier"  # wallet/PGP/handle shared by 2+ actors
    CLEARNET_ACCOUNT = "ClearnetAccount"    # clearnet social / developer / forum profile


class CANONICAL_EDGE_TYPES:
    OPERATES_ON = "OPERATES_ON"            # Actor -> Marketplace
    SELLS = "SELLS"                        # Actor -> Product
    LISTED_ON = "LISTED_ON"                # Product -> Marketplace
    SHARES_IDENTIFIER = "SHARES_IDENTIFIER"  # Actor <-> Actor via SharedIdentifier node
    TRUST = "TRUST"                        # Actor <-> Actor, only with vouch evidence
    CLEARNET_ALIAS = "CLEARNET_ALIAS"      # Actor -> ClearnetAccount (OSINT pivot)


NON_ENTITY_BLOCKLIST = frozenset({
    "wiretransfer",
    "wire",
    "transfer",
    "transfers",
    "carding",
    "vendor",
    "admin",
    "administrator",
    "market",
    "marketplace",
    "seller",
    "unknown",
    "novendorhandledisclosed",
    "novendordisclosed",
    "nohandledisclosed",
    "lead_vendor",
    "leadvendor",
    "contact",
    "support",
})

#: Identifier types eligible to become SharedIdentifier nodes (wallets, PGP,
#: handles). Emails/phones/IPs/banners are Actor fields or evidence only.
SHARED_IDENTIFIER_ELIGIBLE_TYPES = frozenset({
    "BITCOIN_ADDRESS",
    "ETHEREUM_ADDRESS",
    "MONERO_ADDRESS",
    "LITECOIN_ADDRESS",
    "ZCASH_ADDRESS",
    "DOGECOIN_ADDRESS",
    "XRP_ADDRESS",
    "SOLANA_ADDRESS",
    "TRON_ADDRESS",
    "BITCOIN_CASH_ADDRESS",
    "DASH_ADDRESS",
    "CRYPTO_WALLET",
    "CryptoWallet",
    "PGP_KEY_BLOCK",
    "PGP_KEY",
    "PGPKey",
    "TELEGRAM_HANDLE",
    "DISCORD_HANDLE",
    "XMPP_JID",
    "TOX_ID",
    "SESSION_ID",
    "MATRIX_HANDLE",
    "WIRE_HANDLE",
    "ICQ_NUMBER",
    "WICKR_ID",
    "MESSAGING_HANDLE",
    "MessagingHandle",
})

#: Confidence tiers for identifier-based actor correlation.
EXACT_MATCH_CONFIDENCE = 1.0    # exact wallet/PGP/handle match -> merge, ~1.0
FUZZY_MATCH_CONFIDENCE = 0.55   # near-identical handles -> edge, needs review

#: Approval keywords for TRUST edges. A TRUST edge requires one of these
#: phrases AND a handle co-occurring in the same evidence text. Generic
#: "escrow accepted" alone is not enough.
TRUST_EVIDENCE_KEYWORDS = (
    "vouched by",
    "vouch for",
    "verified vendor",
    "verified seller",
    "trusted seller",
    "trusted vendor",
    "trusted by",
)


def normalize_handle(handle: str) -> str:
    """Canonical handle form for comparison: lowercase, strip non-alphanumerics.

    "dark_vendor" vs "dark-vendor-uk" vs "DarkVendor" all normalize
    predictably so near-identical handles can be linked without merging.
    """
    import re
    return re.sub(r"[^a-z0-9]", "", (handle or "").lower())


def is_blocklisted(value: str) -> bool:
    """True if a string is a known non-entity extraction artifact."""
    return normalize_handle(value) in NON_ENTITY_BLOCKLIST


def validate_actor_handle(handle: str) -> tuple[bool, Optional[str]]:
    """Validate whether a candidate handle is a legitimate entity handle or a generic blocklisted artifact."""
    norm = normalize_handle(handle)
    if not norm:
        return False, "empty or non-alphanumeric handle"
    if norm in NON_ENTITY_BLOCKLIST:
        return False, f"generic or blocklisted non-entity term: {handle!r}"
    if len(norm) < 2:
        return False, f"handle too short ({len(norm)} chars): {handle!r}"
    return True, None


def handles_fuzzy_match(a: str, b: str, threshold: float = 0.85) -> bool:
    """True if two handles are near-identical but not exactly equal.

    Exact equality is handled by the merge rule, not here. One handle being a
    strict superstring of the other after normalization (e.g. "darkvendor"
    vs "darkvendoruk") also counts as a fuzzy match.
    """
    from difflib import SequenceMatcher
    na, nb = normalize_handle(a), normalize_handle(b)
    if not na or not nb or na == nb:
        return False
    if na in nb or nb in na:
        return True
    return SequenceMatcher(None, na, nb).ratio() >= threshold


# Metadata for typed relationships lives with the canonical graph vocabulary.
# Consumers should derive their prompt and export representations from these
# definitions rather than maintaining parallel lists.
RELATIONSHIP_TYPE_STIX: dict[str, str] = {
    EDGE_TYPES.CO_APPEARED_ON: "related-to",
    EDGE_TYPES.CO_INVESTIGATION: "related-to",
    EDGE_TYPES.POSTED_BY: "attributed-to",
    EDGE_TYPES.LINKED_TO: "related-to",
    EDGE_TYPES.PAID_TO: "related-to",
    EDGE_TYPES.MEMBER_OF: "member-of",
    EDGE_TYPES.USES: "uses",
    EDGE_TYPES.CLAIMED: "attributed-to",
    EDGE_TYPES.LIKELY_SAME_ACTOR: "related-to",
    EDGE_TYPES.CONFIRMED_SAME_ACTOR: "related-to",
    EDGE_TYPES.FUNDED_BY: "related-to",
    EDGE_TYPES.DROPS: "drops",
    EDGE_TYPES.TARGETS: "targets",
    EDGE_TYPES.EXPLOITS: "exploits",
    EDGE_TYPES.COMMUNICATES_WITH: "communicates-with",
    EDGE_TYPES.CONTROLS: "related-to",
}

# Only typed LLM relationships need endpoint compatibility validation.  The
# key set is also the canonical set exposed to the LLM parser.
RELATIONSHIP_TYPE_COMPATIBILITY: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    EDGE_TYPES.USES: (
        frozenset({"RANSOMWARE_GROUP", "THREAT_ACTOR", "THREAT_ACTOR_HANDLE"}),
        frozenset({"MALWARE_FAMILY", "MALWARE", "TOOL", "SOFTWARE"}),
    ),
    EDGE_TYPES.DROPS: (
        frozenset({"MALWARE_FAMILY", "MALWARE"}),
        frozenset({"MALWARE_FAMILY", "MALWARE", "FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"}),
    ),
    EDGE_TYPES.CONTROLS: (
        frozenset({"RANSOMWARE_GROUP", "THREAT_ACTOR", "THREAT_ACTOR_HANDLE"}),
        frozenset({"CRYPTO_WALLET", "BITCOIN_ADDRESS", "MONERO_ADDRESS", "ETH_ADDRESS", "ETHEREUM_ADDRESS", "LITECOIN_ADDRESS", "ZCASH_ADDRESS", "DOGECOIN_ADDRESS", "XRP_ADDRESS", "SOLANA_ADDRESS", "TRON_ADDRESS", "BITCOIN_CASH_ADDRESS", "DASH_ADDRESS", "IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN", "ENS_DOMAIN", "ONION_URL"}),
    ),
    EDGE_TYPES.TARGETS: (
        frozenset({"RANSOMWARE_GROUP", "THREAT_ACTOR", "THREAT_ACTOR_HANDLE", "MALWARE_FAMILY", "MALWARE"}),
        frozenset({"ORGANIZATION_NAME"}),
    ),
    EDGE_TYPES.EXPLOITS: (
        frozenset({"RANSOMWARE_GROUP", "THREAT_ACTOR", "THREAT_ACTOR_HANDLE", "MALWARE_FAMILY", "MALWARE"}),
        frozenset({"CVE", "CVE_NUMBER", "EXPLOIT_DB_ID"}),
    ),
    EDGE_TYPES.COMMUNICATES_WITH: (
        frozenset({"RANSOMWARE_GROUP", "THREAT_ACTOR", "THREAT_ACTOR_HANDLE", "MALWARE_FAMILY", "MALWARE"}),
        frozenset({"IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN", "ENS_DOMAIN", "ONION_URL", "TELEGRAM_HANDLE", "DISCORD_HANDLE", "XMPP_JID", "TOX_ID", "MATRIX_HANDLE", "WIRE_HANDLE", "ICQ_NUMBER", "WICKR_ID", "PHONE_NUMBER", "EMAIL_ADDRESS"}),
    ),
}



# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class GraphNode:
    """Represents a single entity node in the relationship graph."""

    node_id: str                        # canonical value (wallet address, handle, etc.)
    node_type: str                      # one of NODE_TYPES constants
    first_seen: datetime
    last_seen: datetime
    source_urls: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Represents a directed relationship edge in the graph."""

    source_id: str                      # node_id of the source node
    target_id: str                      # node_id of the target node
    edge_type: str                      # one of EDGE_TYPES constants
    confidence: float                   # 0.0–1.0
    source_url: str                     # page where the relationship was observed
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)
