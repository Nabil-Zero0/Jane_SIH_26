"""
Jane Backend — Profiler & Stylometry Engine
Analyzes extracted dark web text in data/jane.db:
  1. Calculates multi-dimensional writing style fingerprints (Burrows' Delta z-scores).
  2. Measures OpSec failure score (0-100), timezone leaks, and clearnet slips.
  3. Computes pairwise author similarity and dynamically links LIKELY_SAME_AUTHOR edges in the graph.
  4. Exports structured dossier to data/profiler_dossier.json.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("jane.backend.profiler")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

from jane.backend.profiler.stylometry import (
    extract_style_vector,
    compute_similarity,
    are_likely_same_author,
)
from jane.backend.profiler.opsec import (
    run_full_opsec_analysis,
    detect_clearnet_slip,
    detect_timezone_leak,
)


DEFAULT_DB_PATH = REPO_ROOT / "data" / "jane.db"


def analyze_page_profiles() -> Dict[str, Any]:
    """Extracts style vectors and OpSec metrics for all pages with text."""
    conn = sqlite3.connect(DEFAULT_DB_PATH)
    cursor = conn.cursor()

    rows = cursor.execute("""
        SELECT id, url, cleaned_text, scrape_timestamp, byte_size 
        FROM pages 
        WHERE cleaned_text IS NOT NULL AND length(cleaned_text) > 100
    """).fetchall()

    logger.info(f"Loaded {len(rows)} pages for stylometric & OpSec profiling.")

    page_profiles: List[Dict[str, Any]] = []

    for row in rows:
        page_id, url, text, scrape_ts, byte_size = row
        vec = extract_style_vector(text)

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(scrape_ts.replace("Z", "+00:00")) if scrape_ts else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        # OpSec checks
        clearnet_slip_res = detect_clearnet_slip(text)
        tz_leak_res = detect_timezone_leak([{"text": text, "timestamp": ts}])

        # Calculate high-level OpSec score (100 = perfect OpSec, 0 = completely blown)
        score = 85.0
        findings = []
        if clearnet_slip_res.get("detected"):
            score -= 30.0
            findings.append(f"Clearnet slip: {clearnet_slip_res.get('matched_url')}")
        if tz_leak_res.get("detected"):
            score -= 15.0
            findings.append(f"Probable timezone: {tz_leak_res.get('probable_timezone_offset')}")

        word_count = len(text.split())
        if word_count < 100:
            rel_level = "UNRELIABLE"
            rel_warning = "⚠️ Sample too short (<100 words) for forensic attribution"
        elif word_count <= 300:
            rel_level = "TRIAGE_ONLY"
            rel_warning = "⚠️ Triage only (100–300 words, preliminary signal)"
        elif word_count <= 1000:
            rel_level = "MODERATE"
            rel_warning = "✓ Moderate confidence (300–1000 words, basic patterns emerge)"
        else:
            rel_level = "HIGH_CONFIDENCE"
            rel_warning = "✓ High confidence (1000+ words, stable stylometric baseline)"

        profile = {
            "page_id": page_id,
            "url": url,
            "byte_size": byte_size,
            "word_count": word_count,
            "sample_reliability": {
                "level": rel_level,
                "warning": rel_warning,
            },
            "has_style_vector": vec is not None,
            "style_metrics": {
                "avg_word_length": round(vec.get("avg_word_length", 0.0), 2) if vec else None,
                "vocab_richness": round(vec.get("vocabulary_richness", 0.0), 2) if vec else None,
                "punctuation_density": round(vec.get("punctuation_density", 0.0), 2) if vec else None,
                "top_function_words": {
                    k: round(v, 4) for k, v in list(vec.get("function_word_freq", {}).items())[:5]
                } if vec else {},
            },
            "raw_vector": vec,
            "opsec": {
                "opsec_score": max(0.0, score),
                "clearnet_slip": clearnet_slip_res.get("detected", False),
                "timezone_leak": tz_leak_res.get("detected", False),
                "probable_timezone": tz_leak_res.get("probable_timezone_offset"),
                "findings": findings,
            },
        }
        page_profiles.append(profile)

    # Cross-author similarity matrix with feature-level explainability breakdown
    similarities: List[Dict[str, Any]] = []
    attribution_edges: List[Dict[str, Any]] = []

    for i in range(len(page_profiles)):
        for j in range(i + 1, len(page_profiles)):
            p1 = page_profiles[i]
            p2 = page_profiles[j]
            v1 = p1.get("raw_vector")
            v2 = p2.get("raw_vector")

            if v1 and v2:
                sim = compute_similarity(v1, v2)
                is_same, score = are_likely_same_author(v1, v2, threshold=0.75)

                # Feature-level explainability
                fw1 = v1.get("function_word_freq", {})
                fw2 = v2.get("function_word_freq", {})
                all_fws = set(fw1.keys()).union(set(fw2.keys()))
                diffs = []
                for w in all_fws:
                    d = abs(fw1.get(w, 0.0) - fw2.get(w, 0.0))
                    diffs.append((w, d))
                diffs.sort(key=lambda x: x[1])

                top_matching = [{"word": w, "difference": round(d, 4)} for w, d in diffs[:5]]
                top_divergent = [{"word": w, "difference": round(d, 4)} for w, d in diffs[-5:]]

                vocab1 = p1["style_metrics"].get("vocab_richness") or 0.5
                vocab2 = p2["style_metrics"].get("vocab_richness") or 0.5
                len1 = p1["style_metrics"].get("avg_word_length") or 4.5
                len2 = p2["style_metrics"].get("avg_word_length") or 4.5
                punct1 = p1["style_metrics"].get("punctuation_density") or 0.05
                punct2 = p2["style_metrics"].get("punctuation_density") or 0.05

                explainability = {
                    "function_word_cosine": round(sim, 4),
                    "vocab_richness_delta": round(abs(vocab1 - vocab2), 4),
                    "word_length_delta": round(abs(len1 - len2), 4),
                    "punctuation_delta": round(abs(punct1 - punct2), 4),
                    "top_matching_function_words": top_matching,
                    "top_divergent_function_words": top_divergent,
                }

                sim_entry = {
                    "source_url": p1["url"],
                    "target_url": p2["url"],
                    "similarity_score": round(sim, 4),
                    "likely_same_author": is_same,
                    "reliability_warning": p1["sample_reliability"]["warning"] if p1["word_count"] < 300 else p2["sample_reliability"]["warning"],
                    "explainability": explainability,
                }
                similarities.append(sim_entry)

                if is_same:
                    logger.info(
                        f"[!] Attribution alert: {p1['url'][:30]} and {p2['url'][:30]} "
                        f"share {round(sim*100, 2)}% stylometric similarity (LIKELY_SAME_AUTHOR)"
                    )
                    attribution_edges.append(sim_entry)

                    # Persist edge into jane.db
                    ent1 = cursor.execute("SELECT id FROM entities WHERE page_id = ? LIMIT 1", (p1["page_id"],)).fetchone()
                    ent2 = cursor.execute("SELECT id FROM entities WHERE page_id = ? LIMIT 1", (p2["page_id"],)).fetchone()
                    if ent1 and ent2:
                        edge_id = os.urandom(16).hex()
                        cursor.execute("""
                            INSERT OR IGNORE INTO entity_relationships
                            (id, entity_a_id, entity_b_id, relationship_type, confidence, first_seen)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            edge_id,
                            ent1[0],
                            ent2[0],
                            "LIKELY_SAME_AUTHOR",
                            score,
                            datetime.now(timezone.utc).isoformat(),
                        ))
                        conn.commit()


    # Clean raw vectors before serializing
    for p in page_profiles:
        p.pop("raw_vector", None)

    dossier = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profiles_count": len(page_profiles),
        "profiles": page_profiles,
        "cross_comparisons": similarities,
        "attribution_links": attribution_edges,
    }

    out_file = REPO_ROOT / "data" / "profiler_dossier.json"
    out_file.write_text(json.dumps(dossier, indent=2), encoding="utf-8")
    logger.info(f"[+] Profiler dossier generated -> {out_file.name}")
    conn.close()
    return dossier


def run_stylometry(batch_data: Dict[str, Any]) -> Dict[str, Any]:
    """Microservice entrypoint: Computes style vectors and OpSec leak metrics from batch pages."""
    pages = batch_data.get("pages", [])
    profiles = []

    for page in pages:
        text = page.get("cleaned_text", "")
        if not text or len(text) < 30:
            continue

        vec = extract_style_vector(text)
        ts = datetime.now(timezone.utc)
        clearnet_slip = detect_clearnet_slip(text)
        tz_leak = detect_timezone_leak([{"text": text, "timestamp": ts}])

        score = 85.0
        findings = []
        if clearnet_slip.get("detected"):
            score -= 30.0
            findings.append(f"Clearnet slip: {clearnet_slip.get('matched_url')}")
        if tz_leak.get("detected"):
            score -= 15.0
            findings.append(f"Probable timezone: {tz_leak.get('probable_timezone_offset')}")

        profile = {
            "onion_address": page.get("onion_address", ""),
            "url": page.get("url", ""),
            "text_length": len(text),
            "opsec_score": max(0.0, min(100.0, score)),
            "opsec_findings": findings,
            "style_metrics": {
                "avg_word_length": round(vec.get("avg_word_length", 0.0), 2) if vec else None,
                "vocab_richness": round(vec.get("vocabulary_richness", 0.0), 2) if vec else None,
                "punctuation_density": round(vec.get("punctuation_density", 0.0), 2) if vec else None,
            } if vec else {},
        }
        profiles.append(profile)

    return {
        "status": "STYLOMETRY_ANALYZED",
        "batch_id": batch_data.get("batch_id", ""),
        "profiles_count": len(profiles),
        "profiles": profiles,
    }


def compute_reliability_gate(text: str) -> Dict[str, Any]:
    """Evaluates text word count for forensic attribution reliability gating."""
    word_count = len(text.split())
    if word_count < 100:
        rel_level = "UNRELIABLE"
        rel_warning = "⚠️ Sample too short (<100 words) for forensic attribution"
    elif word_count <= 300:
        rel_level = "TRIAGE_ONLY"
        rel_warning = "⚠️ Triage only (100–300 words, preliminary signal)"
    elif word_count <= 1000:
        rel_level = "MODERATE"
        rel_warning = "✓ Moderate confidence (300–1000 words, basic patterns emerge)"
    else:
        rel_level = "HIGH_CONFIDENCE"
        rel_warning = "✓ High confidence (1000+ words, stable stylometric baseline)"
    return {"level": rel_level, "warning": rel_warning, "word_count": word_count}


def rank_candidate_authors(
    test_text: str,
    candidate_profiles: Any,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    """
    Computes Burrows' Delta similarities between unknown text and candidate profiles,
    converting raw distances into calibrated softmax probabilities with feature explainability.
    """
    import math

    if not test_text or not candidate_profiles:
        return []

    test_vec = extract_style_vector(test_text)
    if not test_vec:
        return []

    # Normalize candidate input (can be dict of name->text or list of profile dicts)
    candidates: List[Dict[str, Any]] = []
    if isinstance(candidate_profiles, dict):
        for name, item in candidate_profiles.items():
            if isinstance(item, str):
                vec = extract_style_vector(item)
                candidates.append({"candidate": name, "raw_vector": vec})
            elif isinstance(item, dict):
                candidates.append(dict(item, candidate=name))
    elif isinstance(candidate_profiles, list):
        for c in candidate_profiles:
            if isinstance(c, dict):
                cand_copy = dict(c)
                if "text" in cand_copy and not cand_copy.get("raw_vector"):
                    cand_copy["raw_vector"] = extract_style_vector(cand_copy["text"])
                candidates.append(cand_copy)

    scores = []
    for cand in candidates:
        cand_vec = cand.get("raw_vector") or cand.get("style_vector")
        if not cand_vec and "style_metrics" in cand:
            cand_vec = cand["style_metrics"]
        if cand_vec:
            sim = compute_similarity(test_vec, cand_vec)
            name = cand.get("candidate") or cand.get("url") or "Unknown"
            
            # Feature-level explainability (closest function words)
            test_fw = test_vec.get("function_word_freq", {})
            cand_fw = cand_vec.get("function_word_freq", {})
            common = set(test_fw.keys()) & set(cand_fw.keys())
            matching_features = sorted(common, key=lambda w: abs(test_fw[w] - cand_fw[w]))[:5] if common else []

            scores.append((name, sim, matching_features))

    if not scores:
        return []

    # Softmax scaling factor
    exps = [math.exp(s[1] * 4.0) for s in scores]
    sum_exps = sum(exps) or 1.0

    ranked = []
    for (name, sim, features), exp_v in zip(scores, exps):
        prob = round(exp_v / sum_exps, 4)
        ranked.append({
            "candidate": name,
            "candidate_author": name,
            "similarity": round(sim, 4),
            "match_probability": prob,
            "explainability": {
                "top_matching_features": features,
            },
        })

    ranked.sort(key=lambda x: x["match_probability"], reverse=True)
    return ranked[:top_k]


def main():
    parser = argparse.ArgumentParser(description="Jane Profiler & Stylometry Engine")
    parser.add_argument("--batch", "-b", type=str, help="Path to Scout batch JSON file")
    args = parser.parse_args()

    if args.batch:
        batch_path = Path(args.batch)
        if not batch_path.exists():
            print(f"Error: {args.batch} not found")
            sys.exit(1)
        with open(batch_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        res = run_stylometry(data)
        print(json.dumps(res, indent=2))
    else:
        dossier = analyze_page_profiles()
        print(f"\n[+] Profiling Complete:")
        print(f"    Profiles Analyzed: {dossier['profiles_count']}")
        print(f"    Pairwise Comparisons: {len(dossier['cross_comparisons'])}")
        print(f"    Attribution Links (LIKELY_SAME_AUTHOR): {len(dossier['attribution_links'])}")
        for link in dossier["attribution_links"]:
            print(f"    -> {link['source_url'][:40]} <==> {link['target_url'][:40]} ({round(link['similarity_score']*100, 1)}% match)")


if __name__ == "__main__":
    main()
