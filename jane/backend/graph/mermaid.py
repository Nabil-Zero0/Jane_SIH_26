"""
Jane Backend — Multi-View Mermaid Generator
Generates syntax-safe, modular Mermaid.js diagrams from investigation graph data.
Includes safe escaping for hostile web characters and 6 scoped forensic views.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
import networkx as nx

from jane.backend.graph.model import INFERENCE_RELATIONS, EntityType, RelationType


def mermaid_label(value: str) -> str:
    """Escapes hostile characters to prevent Mermaid parser syntax errors."""
    clean = str(value or "")
    clean = clean.replace("\\", "\\\\")
    clean = clean.replace('"', "'")
    clean = clean.replace("\n", " ")
    clean = clean.replace("[", "(")
    clean = clean.replace("]", ")")
    clean = clean.replace("{", "(")
    clean = clean.replace("}", ")")
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean[:200]


def _safe_node_id(raw_id: str) -> str:
    """Converts arbitrary strings into valid Mermaid node identifiers."""
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", str(raw_id))
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"n_{cleaned}"
    return cleaned[:32]


def generate_mermaid_views(G: nx.MultiDiGraph) -> Dict[str, str]:
    """
    Generates 6 modular Mermaid views from an in-memory NetworkX MultiDiGraph:
      1. site_overview
      2. actor_account_view
      3. product_service_view
      4. infrastructure_view
      5. evidence_only_view
      6. inference_view
      7. full_view
    """
    views = {
        "full_view": "graph LR\n",
        "site_overview": "graph TD\n",
        "actor_account_view": "graph LR\n",
        "product_service_view": "graph LR\n",
        "infrastructure_view": "graph TD\n",
        "evidence_only_view": "graph LR\n",
        "inference_view": "graph LR\n",
    }

    edge_lines: Dict[str, List[str]] = {k: [] for k in views}
    defined_nodes: Dict[str, set[str]] = {k: set() for k in views}

    for u, v, data in G.edges(data=True):
        u_data = G.nodes.get(u, {})
        v_data = G.nodes.get(v, {})

        u_id = _safe_node_id(u)
        v_id = _safe_node_id(v)

        u_type = str(u_data.get("node_type", "DEFAULT")).upper()
        v_type = str(v_data.get("node_type", "DEFAULT")).upper()

        u_lbl = mermaid_label(u_data.get("label", u))
        v_lbl = mermaid_label(v_data.get("label", v))

        edge_type = str(data.get("edge_type", "RELATED_TO")).upper()
        is_infer = edge_type in {r.value for r in INFERENCE_RELATIONS} or data.get("is_inference", False)

        u_str = f'{u_id}["{u_type}: {u_lbl}"]'
        v_str = f'{v_id}["{v_type}: {v_lbl}"]'

        arrow = "-.->|" if is_infer else "-->|"
        edge_decl = f"    {u_id} {arrow}{edge_type}| {v_id}"

        def record(view_key: str):
            if u_id not in defined_nodes[view_key]:
                edge_lines[view_key].append(f"    {u_str}")
                defined_nodes[view_key].add(u_id)
            if v_id not in defined_nodes[view_key]:
                edge_lines[view_key].append(f"    {v_str}")
                defined_nodes[view_key].add(v_id)
            edge_lines[view_key].append(edge_decl)

        # 1. Full view
        record("full_view")

        # 2. Site overview
        if any(t in (u_type, v_type) for t in ("SITE", "PAGE", "DOMAIN", "ONION_URL")):
            record("site_overview")

        # 3. Actor & account view
        if any(t in (u_type, v_type) for t in ("ALIAS", "ACCOUNT", "PERSON_ALIAS", "THREAT_ACTOR", "TELEGRAM_HANDLE", "EMAIL")):
            record("actor_account_view")

        # 4. Product & service view
        if any(t in (u_type, v_type) for t in ("PRODUCT", "SERVICE", "CRYPTO_ADDRESS", "CRYPTO_WALLET", "COMMODITY")):
            record("product_service_view")

        # 5. Infrastructure view
        if any(t in (u_type, v_type) for t in ("IP_ADDRESS", "FAVICON_MMH3", "SERVER_BANNER", "DOMAIN", "SITE")):
            record("infrastructure_view")

        # 6. Evidence-only view (exclude inference edges)
        if not is_infer:
            record("evidence_only_view")

        # 7. Inference view (only inference edges)
        if is_infer:
            record("inference_view")

    result: Dict[str, str] = {}
    for k, base_hdr in views.items():
        lines = edge_lines[k]
        if lines:
            result[k] = base_hdr + "\n".join(lines) + "\n"
        else:
            result[k] = base_hdr + "    empty[\"No entities in this view\"]\n"

    return result


def validate_mermaid_syntax(text: str) -> bool:
    """Validates Mermaid flowchart syntax using pure stdlib checks.
    
    Checks header, balanced delimiters, quote parity, and link presence.
    Returns True if structurally valid, False if malformed.
    """
    if not text or not isinstance(text, str):
        return False

    cleaned = text.strip()
    if cleaned.startswith("```"):
        # Strip outer code fences if model included them
        lines = [ln for ln in cleaned.splitlines() if not ln.strip().startswith("```")]
        cleaned = "\n".join(lines).strip()

    if not cleaned:
        return False

    # 1. Header check
    first_line = cleaned.splitlines()[0].strip().lower()
    if not (first_line.startswith("flowchart") or first_line.startswith("graph")):
        return False

    # 2. Must contain at least one node definition or arrow link
    has_arrow = any(tok in cleaned for tok in ("-->", "---", "-.->", "==>"))
    has_node = bool(re.search(r'\[.+?\]|\(.+?\)|\{.+?\}|\(\[.+?\]\)|\[\(.+?\)\]', cleaned))
    if not (has_arrow or has_node):
        return False

    # 3. Delimiter balance check
    # Ignore characters inside quotes or comments
    in_quotes = False
    stack = []
    pairs = {']': '[', ')': '(', '}': '{'}

    for idx, char in enumerate(cleaned):
        if char == '"' and (idx == 0 or cleaned[idx - 1] != '\\'):
            in_quotes = not in_quotes
            continue
        if in_quotes:
            continue
        if char in ('[', '(', '{'):
            stack.append(char)
        elif char in (']', ')', '}'):
            if not stack or stack[-1] != pairs[char]:
                return False
            stack.pop()

    if in_quotes or stack:
        return False

    return True
