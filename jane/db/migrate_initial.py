"""
DEMO SEED DATA ONLY — DO NOT RUN IN AUTOMATED PIPELINE.
This script populates initial demo fixtures for local presentation and testing.
It is never called automatically on application startup or database initialization.
"""

import json
from pathlib import Path
from jane.db.database import (
    init_db,
    create_investigation,
    update_investigation_status,
    save_onion_page,
    save_threat_actor,
    save_identifier,
    save_graph_node,
    save_graph_edge,
    get_db_connection,
)

def run_migration():
    repo_root = Path(__file__).resolve().parent.parent.parent
    init_db()
    
    # 1. Create or get default investigation
    inv_id = "inv_sih_26151_alpha"
    create_investigation(
        query="wire transfer carding dumps",
        max_onions=5,
        max_depth=1,
        inv_id=inv_id,
    )
    
    # 2. Ingest processed batch drops
    processed_dir = repo_root / "data" / "drop" / "processed"
    pages_count = 0
    if processed_dir.exists():
        for p in processed_dir.glob("batch_*.json"):
            try:
                bdata = json.loads(p.read_text(encoding="utf-8"))
                for pg in bdata.get("pages", []):
                    url = pg.get("url", "")
                    title = pg.get("title", "")
                    cleaned_text = pg.get("cleaned_text", "")
                    raw_html = pg.get("raw_html", "")
                    
                    raw_html_path = ""
                    if raw_html:
                        # Save raw HTML to disk in jane/data/raw/
                        raw_dir = repo_root / "jane" / "data" / "raw"
                        raw_dir.mkdir(parents=True, exist_ok=True)
                        f_name = f"page_{hash(url) & 0xffffffff:08x}.html"
                        f_path = raw_dir / f_name
                        f_path.write_text(raw_html, encoding="utf-8")
                        raw_html_path = str(f_path)
                        
                    pid = save_onion_page(
                        investigation_id=inv_id,
                        url=url,
                        title=title,
                        raw_html_path=raw_html_path,
                        cleaned_text=cleaned_text[:50000] if cleaned_text else "",
                        server_banner="nginx",
                        favicon_mmh3="-661270997",
                        etag='"dlgtxk82ab0472uf"',
                    )
                    pages_count += 1
            except Exception as e:
                print(f"Error processing {p}: {e}")

    # 3. Ingest threat actor profile
    aid = save_threat_actor(
        investigation_id=inv_id,
        designated_id="TA-ORION-ALPHA",
        primary_handle="wire: transfer",
        threat_category="Financial Fraud / Carding",
        attributed_onions="unimktsvidgh7bzkgxclqvpioubz7cpn5ty4jftnmuxx6ish6xudebqd.onion, dgquftlj2h3rhbalvz6o6s7ilg32bg763eqjyb76wlv4w2cndfzzrdid.onion",
        confidence=0.932,
        stylometry_summary="Burrows' Delta stylometric vector correlation (88.7%). Consistent UTC+5 active clock-skew window. Same Telegram vendor alias across multiple carding mirrors.",
    )

    # 4. Ingest sample identifiers
    sample_idents = [
        ("MessagingHandle", "wire: transfer", "Contact lead vendor via wire: transfer for bulk dumps.", 1.0),
        ("CryptoWallet", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "Escrow address accepted for high balance Visa/MasterCard dumps.", 0.95),
        ("ServerBanner", "nginx", "HTTP Server response header on port 80", 1.0),
        ("FaviconHash", "-661270997", "MurmurHash3 computed from favicon.ico (matches clearnet origin)", 1.0),
        ("HTTP_ETag", '"dlgtxk82ab0472uf"', "Exact entity tag match across hidden services", 0.98),
    ]
    for itype, val, quote, conf in sample_idents:
        save_identifier(
            investigation_id=inv_id,
            itype=itype,
            value=val,
            actor_id=aid,
            evidence_quote=quote,
            confidence=conf,
        )

    # 5. Ingest Graph Snapshot
    graph_path = repo_root / "data" / "graph_snapshot.json"
    if graph_path.exists():
        gdata = json.loads(graph_path.read_text(encoding="utf-8"))
        for n in gdata.get("elements", {}).get("nodes", []):
            d = n.get("data", {})
            save_graph_node(
                investigation_id=inv_id,
                node_id=d.get("id", ""),
                label=d.get("label", d.get("id", "")),
                node_type=d.get("node_type", "Entity"),
                community=d.get("community", 1),
                degree=d.get("degree", 1),
                metadata=d,
            )
        for e in gdata.get("elements", {}).get("edges", []):
            d = e.get("data", {})
            save_graph_edge(
                investigation_id=inv_id,
                source=d.get("source", ""),
                target=d.get("target", ""),
                edge_type=d.get("edge_type", "RELATED_TO"),
                confidence=d.get("confidence", 1.0),
                evidence_quote=d.get("evidence_quote", ""),
            )

    update_investigation_status(inv_id, "COMPLETED", pages_count)
    print(f"Migration successful! Investigation {inv_id} created with {pages_count} pages.")

if __name__ == "__main__":
    run_migration()
