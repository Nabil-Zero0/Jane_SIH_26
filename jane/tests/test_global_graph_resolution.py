import json
from pathlib import Path

from jane.backend.graph.connector import ingest_threat_graph
from jane.db.database import create_investigation, get_global_graph_summary, get_db_connection


def _write_graph(tmp_path: Path, inv_id: str, *, handle: str, market: str, pgp: str | None = None):
    workspace = tmp_path / inv_id / "graph"
    workspace.mkdir(parents=True)
    actor = {
        "id": f"raw_{inv_id}",
        "type": "actor",
        "handle": handle,
        "evidence_quote": f"{handle} operates {market}",
    }
    if pgp:
        actor["pgp_keys"] = [pgp]
    payload = {
        "investigation_id": inv_id,
        "nodes": [
            actor,
            {
                "id": f"market_{inv_id}",
                "type": "marketplace",
                "name_or_domain": market,
                "evidence_quote": f"{market} storefront",
            },
        ],
        "edges": [{
            "source": f"raw_{inv_id}",
            "target": f"market_{inv_id}",
            "type": "operates_on",
            "confidence": 0.9,
            "evidence_quote": f"{handle} operates {market}",
        }],
    }
    (workspace / "threat_graph.json").write_text(json.dumps(payload), encoding="utf-8")
    return workspace.parent


def test_same_username_does_not_merge_across_investigations(tmp_path):
    create_investigation("first", inv_id="inv_one")
    create_investigation("second", inv_id="inv_two")
    ingest_threat_graph("inv_one", _write_graph(tmp_path, "inv_one", handle="same_name", market="market-one.onion"))
    ingest_threat_graph("inv_two", _write_graph(tmp_path, "inv_two", handle="same_name", market="market-two.onion"))

    conn = get_db_connection()
    rows = conn.execute("SELECT id FROM graph_nodes WHERE node_type = 'Actor'").fetchall()
    conn.close()
    assert len(rows) == 2


def test_strong_identity_merges_and_global_edge_keeps_provenance(tmp_path):
    create_investigation("first", inv_id="inv_one")
    create_investigation("second", inv_id="inv_two")
    ingest_threat_graph("inv_one", _write_graph(tmp_path, "inv_one", handle="same_actor", market="market-one.onion", pgp="PGP-ABC"))
    ingest_threat_graph("inv_two", _write_graph(tmp_path, "inv_two", handle="same_actor", market="market-one.onion", pgp="PGP-ABC"))

    summary = get_global_graph_summary()
    actor_nodes = [node for node in summary["graph_elements"]["nodes"] if node["data"]["node_type"] == "Actor"]
    assert len(actor_nodes) == 1
    assert set(actor_nodes[0]["data"]["source_investigations"]) == {"inv_one", "inv_two"}

    edges = [edge for edge in summary["graph_elements"]["edges"] if edge["data"]["edge_type"] == "OPERATES_ON"]
    assert len(edges) == 1
    assert {inv for item in edges[0]["data"]["provenance"] for inv in item["investigations"]} == {"inv_one", "inv_two"}
