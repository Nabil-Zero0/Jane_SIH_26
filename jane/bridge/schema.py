"""
Jane Bridge — Standard Schema for Collector Data Drops
Preserves raw HTML, metadata, and extracted artifacts with zero data loss.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

@dataclass
class ScrapedPage:
    url: str
    onion_address: str
    raw_content_hash: str          # SHA-256 hex digest of raw content
    byte_size: int
    http_status: int
    title: str = ""
    cleaned_text: str = ""         # Visible text (headers, footers, body included)
    raw_html: str = ""             # 100% complete raw HTML (zero data loss)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    outbound_links: List[str] = field(default_factory=list)
    image_urls: List[str] = field(default_factory=list)
    template_hash: Optional[str] = None
    content_diff_ratio: Optional[float] = None
    scrape_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

@dataclass
class BatchDrop:
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_agent: str = "scout"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    query: Optional[str] = None
    page_count: int = 0
    pages: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "source_agent": self.source_agent,
            "created_at": self.created_at,
            "query": self.query,
            "page_count": len(self.pages),
            "pages": self.pages,
        }
