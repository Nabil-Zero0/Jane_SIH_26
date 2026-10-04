"""
Jane Backend — Controlled Vocabulary & Provenance Graph Model
Defines standardized entity and relationship taxonomy, separating observed facts
from inferences, and enforcing traceable evidence provenance.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class EntityType(str, Enum):
    SITE = "SITE"
    PAGE = "PAGE"
    ACCOUNT = "ACCOUNT"
    ALIAS = "ALIAS"
    ORGANISATION = "ORGANISATION"
    PRODUCT = "PRODUCT"
    SERVICE = "SERVICE"
    CRYPTO_ADDRESS = "CRYPTO_ADDRESS"
    PGP_KEY = "PGP_KEY"
    EMAIL = "EMAIL"
    TELEGRAM_HANDLE = "TELEGRAM_HANDLE"
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    LOCATION = "LOCATION"
    DATE = "DATE"
    DEFAULT = "DEFAULT"


class RelationType(str, Enum):
    # Factual relationships (observed in text / DOM)
    POSTED_ON = "POSTED_ON"
    USES_ALIAS = "USES_ALIAS"
    SELLS = "SELLS"
    OFFERS = "OFFERS"
    CONTACTS = "CONTACTS"
    MENTIONS = "MENTIONS"
    OWNS = "OWNS"
    CONTROLS = "CONTROLS"
    LINKS_TO = "LINKS_TO"
    USES_CRYPTO_ADDRESS = "USES_CRYPTO_ADDRESS"
    USES_PGP_KEY = "USES_PGP_KEY"
    LOCATED_IN = "LOCATED_IN"

    # Inferred relationships (computed via stylometry, infra correlation, etc.)
    SAME_TEMPLATE = "SAME_TEMPLATE"
    LIKELY_SAME_AUTHOR = "LIKELY_SAME_AUTHOR"


INFERENCE_RELATIONS: Set[RelationType] = {
    RelationType.SAME_TEMPLATE,
    RelationType.LIKELY_SAME_AUTHOR,
}


@dataclass
class EvidenceQuote:
    chunk_id: str
    quote: str
    confidence: float = 1.0


@dataclass
class GraphNode:
    id: str
    label: str
    node_type: EntityType
    community: int = 1
    degree: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "node_type": self.node_type.value,
            "community": self.community,
            "degree": self.degree,
            **self.metadata,
        }


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    edge_type: RelationType
    confidence: float = 1.0
    evidence: List[EvidenceQuote] = field(default_factory=list)
    basis: str = "explicit_text"  # "explicit_text", "burrows_delta_zscore", "dom_template_hash", "shodan_ip_banner"
    review_status: str = "unreviewed"  # "unreviewed", "verified", "rejected"

    @property
    def is_inference(self) -> bool:
        return self.edge_type in INFERENCE_RELATIONS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type.value,
            "confidence": self.confidence,
            "basis": self.basis,
            "review_status": self.review_status,
            "is_inference": self.is_inference,
            "evidence": [asdict(e) for e in self.evidence],
        }
