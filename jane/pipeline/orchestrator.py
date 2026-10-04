"""
Jane Pipeline Orchestrator — Pure Microservice Coordinator
Connects each independent intelligence stage in sequence:
  Query -> [1. Scout] -> [2. Extractor] -> [3. Locksmith] -> [4. Stylometry] -> [5. AI Layer] -> [6. Graph] -> SQLite & Dashboard

Zero inline scraping, regex, or AI logic inside this coordinator.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional
import uuid

# Database layer
from jane.db.database import (
    init_db,
    create_investigation,
    update_investigation_status,
    get_investigation_summary,
    record_search_run,
    insert_search_hits,
    insert_evidence_chunks,
)

# Microservice increments
from jane.pipeline.query_planner import plan_queries
from jane.collector.providers import get_providers, safe_search, SearchHit
from jane.collector.target_ranker import rank_targets
from jane.ai.chunker import chunk_text
from jane.backend.extractor import run_extraction
from jane.backend.locksmith.correlator import run_locksmith
from jane.backend.profiler.analyzer import run_stylometry
from jane.ai.opencode_bridge import (
    run_ai,
    generate_forensic_profile,
    create_job_workspace,
    create_investigation_workspace,
    create_investigation_session,
    start_investigation_analysis,
    start_osint_extraction,
    start_graph_synthesis,
    start_mermaid_enrichment,
    wait_for_investigation_report,
    wait_for_opencode_file,
    wait_for_mermaid_file,
    build_concentric_cytoscape_fallback,
    update_investigation_workspace,
    write_investigation_artifacts,
    TIMEOUT_TURN1_FANOUT,
    TIMEOUT_TURN2_ATTRIBUTION,
    TIMEOUT_TURN25_OSINT,
    TIMEOUT_TURN3_GRAPH,
    TIMEOUT_TURN35_MERMAID,
)
from jane.backend.graph.connector import run_graph, ingest_threat_graph
from jane.backend.osint_pivot import run_osint_enrichment

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [orchestrator] %(message)s")
logger = logging.getLogger("jane.pipeline.orchestrator")


def get_paths() -> Dict[str, Path]:
    repo_root = Path(__file__).resolve().parent.parent.parent
    base = repo_root / "jane" / "data"
    jobs_pending = base / "jobs" / "pending"
    jobs_running = base / "jobs" / "running"
    jobs_completed = base / "jobs" / "completed"
    logs_dir = base / "jobs" / "logs"
    drop_incoming = base / "drop" / "incoming"
    drop_processing = base / "drop" / "processing"
    drop_processed = base / "drop" / "processed"
    raw_dir = base / "raw"
    workspaces_dir = base / "workspaces"
    investigations_dir = base / "investigations"

    for d in [jobs_pending, jobs_running, jobs_completed, logs_dir, drop_incoming, drop_processing, drop_processed, raw_dir, workspaces_dir, investigations_dir]:
        d.mkdir(parents=True, exist_ok=True)

    return {
        "repo_root": repo_root,
        "base": base,
        "jobs_pending": jobs_pending,
        "jobs_running": jobs_running,
        "jobs_completed": jobs_completed,
        "logs_dir": logs_dir,
        "drop_incoming": drop_incoming,
        "drop_processing": drop_processing,
        "drop_processed": drop_processed,
        "raw_dir": raw_dir,
        "workspaces_dir": workspaces_dir,
        "investigations_dir": investigations_dir,
    }


def log_event(inv_id: str, stage: str, message: str, level: str = "INFO") -> None:
    paths = get_paths()
    log_file = paths["logs_dir"] / f"{inv_id}.json"
    logs = []
    if log_file.exists():
        try:
            logs = json.loads(log_file.read_text(encoding="utf-8"))
        except Exception:
            logs = []
    entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "stage": stage,
        "message": message,
        "level": level,
    }
    logs.append(entry)
    log_file.write_text(json.dumps(logs, indent=2), encoding="utf-8")
    logger.info(f"[{stage}] {message}")


def get_investigation_logs(inv_id: str) -> List[Dict[str, Any]]:
    paths = get_paths()
    log_file = paths["logs_dir"] / f"{inv_id}.json"
    if log_file.exists():
        try:
            return json.loads(log_file.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def trigger_whonix_scout(query: str, max_onions: int = 2, max_depth: int = 1, job_id: Optional[str] = None) -> bool:
    """Invokes Scout in Whonix-Workstation via VirtualBox guest control."""
    vbox = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    if not Path(vbox).exists():
        logger.warning("VBoxManage.exe not found on host; skipping direct guest invocation.")
        return False

    manifest_arg = ""
    if job_id:
        manifest_arg = f" --target-manifest /media/sf_Jane_SIH_26/jane/data/jobs/pending/job_{job_id}.json"
    cmd = [
        vbox, "guestcontrol", "Whonix-Workstation-LXQt", "run",
        "--username", "user", "--password", "changeme",
        "--exe", "/bin/bash", "--",
        "-c", f"cd /media/sf_Jane_SIH_26 && torsocks python3 -m jane.collector.scout --query '{query}' --max-targets {max_onions} --max-pages {max_depth}{manifest_arg}"
    ]
    try:
        logger.info(f"Triggering Whonix Tor Scout for query '{query}'...")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return proc.returncode == 0
    except Exception as e:
        logger.warning(f"Could not trigger Whonix guest directly: {e}")
        return False


def dispatch_investigation_job(
    query: str,
    max_onions: int = 3,
    max_depth: int = 1,
    fanout_count: int = 3,
    fanout_queries: Optional[List[str]] = None,
    providers: Optional[List[str]] = None,
) -> str:
    paths = get_paths()
    init_db()
    
    inv_id = f"inv_{uuid.uuid4().hex[:8]}"
    create_investigation(query=query, max_onions=max_onions, max_depth=max_depth, inv_id=inv_id)
    investigations_dir = paths.get("investigations_dir", paths["base"] / "investigations")
    investigation_workspace = create_investigation_workspace(inv_id, query, investigations_dir)
    opencode_session_id = create_investigation_session(investigation_workspace)

    # 1. Query Fanout (Turn 1)
    if not fanout_queries:
        plan = plan_queries(query, max_queries=fanout_count, use_llm=bool(opencode_session_id), session_id=opencode_session_id, workspace=investigation_workspace)
        active_fanout = [q.text for q in plan.queries]
    else:
        active_fanout = [q.strip() for q in fanout_queries if q.strip()]
        if not active_fanout:
            active_fanout = [query]

    _write = lambda path, value: path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    fanout_payload = plan.to_dict() if not fanout_queries else {
        "original_query": query,
        "queries": [{"text": q, "purpose": "provided"} for q in active_fanout],
        "generation_source": "provided",
    }
    _write(investigation_workspace / "queries/fanout.json", fanout_payload)
    _write(investigation_workspace / "queries/generated.json", fanout_payload)
    
    # Save the sequential queue state
    queue_data = {
        "investigation_id": inv_id,
        "original_query": query,
        "queries": active_fanout,
        "current_index": 0,
        "max_onions": max_onions,
        "max_depth": max_depth,
        "opencode_session_id": opencode_session_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _write(investigation_workspace / "queries/queue.json", queue_data)

    update_investigation_workspace(investigation_workspace, status="FANOUT_GENERATED", opencode_session_id=opencode_session_id)
    update_investigation_status(inv_id, "FANOUT_GENERATED")

    # OpSec Rule: Zero Clearnet Darknet Search on Host!
    # All discovery and crawling executes strictly inside Whonix via Tor.
    # Dispatch sub-job 0 directly to Whonix with selected_targets: [] to trigger Whonix Scout discovery.
    first_query = active_fanout[0]
    job_id = f"{inv_id}_q0"
    job_data = {
        "job_id": job_id,
        "investigation_id": inv_id,
        "query_index": 0,
        "total_queries": len(active_fanout),
        "query": first_query,
        "fanout_queries": active_fanout,
        "ranked_targets": [],
        "selected_targets": [],
        "investigation_workspace": str(investigation_workspace),
        "opencode_session_id": opencode_session_id,
        "max_onions": max_onions,
        "max_depth": max_depth,
        "dispatched_at": datetime.now(timezone.utc).isoformat(),
    }

    job_file = paths["jobs_pending"] / f"job_{job_id}.json"
    temp_job = job_file.with_suffix(".json.tmp")
    temp_job.write_text(json.dumps(job_data, indent=2), encoding="utf-8")
    temp_job.replace(job_file)

    log_event(inv_id, "QUEUED", f"Dispatched query 1/{len(active_fanout)}: '{first_query}' to Whonix daemon (Tor search & crawl)", "INFO")
    update_investigation_status(inv_id, "QUEUED")
    return inv_id


def process_batch_file(batch_path: Path) -> Optional[str]:
    """Coordinates microservices in sequence for an incoming Scout batch."""
    paths = get_paths()
    with open(batch_path, "r", encoding="utf-8") as f:
        batch_data = json.load(f)

    raw_id = batch_data.get("batch_id") or batch_path.stem.replace("batch_", "")
    if "_q" in raw_id:
        inv_id = raw_id.split("_q")[0]
        try:
            sub_index = int(raw_id.split("_q")[1])
        except Exception:
            sub_index = None
    else:
        inv_id = raw_id
        sub_index = None

    create_investigation(query=batch_data.get("query", "darkweb_scan"), inv_id=inv_id)
    workspace = Path(batch_data.get("investigation_workspace", "")) if batch_data.get("investigation_workspace") else paths.get("investigations_dir", paths["base"] / "investigations") / inv_id
    if not workspace.exists():
        workspace = create_investigation_workspace(inv_id, batch_data.get("query", "darkweb_scan"), workspace.parent)

    queue_file = workspace / "queries" / "queue.json"
    queue_data = None
    if queue_file.exists():
        try:
            queue_data = json.loads(queue_file.read_text(encoding="utf-8"))
        except Exception:
            queue_data = None

    pages = batch_data.get("pages", [])
    query_text = batch_data.get("query", "")

    _write_json = lambda path, val: path.write_text(json.dumps(val, indent=2), encoding="utf-8")

    # Ingest this sub-batch's pages into shared workspace
    if pages:
        log_event(inv_id, "WHONIX_INGEST", f"Ingested {len(pages)} onion pages for query '{query_text}'", "SUCCESS")
        
        # Deterministic chunks for this sub-batch
        all_chunks: List[Dict[str, Any]] = []
        for p in pages:
            p_text = p.get("cleaned_text", "")
            p_url = p.get("url", "")
            p_id = hashlib.sha256(p_url.encode("utf-8")).hexdigest()[:16]
            c_list = chunk_text(p_text, page_id=p_id, url=p_url, investigation_id=inv_id)
            all_chunks.extend([c.to_dict() for c in c_list])
        if all_chunks:
            insert_evidence_chunks(all_chunks)

        # Save individual page artifacts to workspace/html/ and workspace/pages/
        (workspace / "html").mkdir(parents=True, exist_ok=True)
        for page in pages:
            url = page.get("url", "")
            target_id = "target_" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
            target_dir = workspace / "pages" / target_id
            target_dir.mkdir(parents=True, exist_ok=True)
            raw = page.get("raw_html", "")
            if raw:
                (target_dir / "raw.html").write_text(raw, encoding="utf-8")
                (workspace / "html" / f"{target_id}.html").write_text(raw, encoding="utf-8")
            (target_dir / "cleaned.txt").write_text(page.get("cleaned_text", ""), encoding="utf-8")
            _write_json(target_dir / "metadata.json", {k: v for k, v in page.items() if k not in {"raw_html", "cleaned_text"}})
            _write_json(target_dir / "headers.json", page.get("response_headers", page.get("headers", {})))
            _write_json(target_dir / "links.json", {"outbound_links": page.get("outbound_links", [])})
    else:
        logger.warning(f"Batch {batch_path.name} returned zero pages for query '{query_text}'.")
        log_event(inv_id, "WHONIX_EMPTY", f"Whonix Scout captured 0 pages for query '{query_text}'", "WARNING")

    # Check if more queries remain in the sequential fanout queue
    if queue_data and sub_index is not None:
        queries = queue_data.get("queries", [])
        next_idx = sub_index + 1
        if next_idx < len(queries):
            next_query = queries[next_idx]
            queue_data["current_index"] = next_idx
            _write_json(queue_file, queue_data)

            next_job_id = f"{inv_id}_q{next_idx}"
            next_job_data = {
                "job_id": next_job_id,
                "investigation_id": inv_id,
                "query_index": next_idx,
                "total_queries": len(queries),
                "query": next_query,
                "fanout_queries": queries,
                "ranked_targets": [],
                "selected_targets": [],
                "investigation_workspace": str(workspace),
                "opencode_session_id": queue_data.get("opencode_session_id"),
                "max_onions": queue_data.get("max_onions", 2),
                "max_depth": queue_data.get("max_depth", 1),
                "dispatched_at": datetime.now(timezone.utc).isoformat(),
            }
            next_job_file = paths["jobs_pending"] / f"job_{next_job_id}.json"
            temp_next = next_job_file.with_suffix(".json.tmp")
            temp_next.write_text(json.dumps(next_job_data, indent=2), encoding="utf-8")
            temp_next.replace(next_job_file)

            update_investigation_status(inv_id, f"CRAWLING_Q{next_idx}")
            log_event(inv_id, "QUEUED", f"Dispatched query {next_idx + 1}/{len(queries)}: '{next_query}' to Whonix daemon", "INFO")

            # Move current batch to processed and wait for next sub-batch
            dest = paths["drop_processed"] / batch_path.name
            try:
                batch_path.replace(dest)
            except Exception:
                pass
            return inv_id

    # -----------------------------------------------------------------------
    # Final Stage: All fanout queries completed. Consolidate evidence.
    # -----------------------------------------------------------------------
    all_pages: List[Dict[str, Any]] = []
    pages_dir = workspace / "pages"
    if pages_dir.exists():
        for p_dir in pages_dir.iterdir():
            if p_dir.is_dir():
                meta_file = p_dir / "metadata.json"
                txt_file = p_dir / "cleaned.txt"
                raw_file = p_dir / "raw.html"
                if meta_file.exists():
                    try:
                        p_data = json.loads(meta_file.read_text(encoding="utf-8"))
                        if txt_file.exists():
                            p_data["cleaned_text"] = txt_file.read_text(encoding="utf-8")
                        if raw_file.exists():
                            p_data["raw_html"] = raw_file.read_text(encoding="utf-8")
                        all_pages.append(p_data)
                    except Exception:
                        pass
    if not all_pages and pages:
        all_pages = pages

    if not all_pages:
        logger.warning(f"Investigation {inv_id} ended with zero collected pages across all queries.")
        update_investigation_status(inv_id, "FAILED_COLLECTION", 0)
        log_event(inv_id, "FAILED_COLLECTION", "Zero pages captured across all fanout queries", "ERROR")
        dest = paths["drop_processed"] / batch_path.name
        try:
            batch_path.replace(dest)
        except Exception:
            pass
        return inv_id

    update_investigation_status(inv_id, "COLLECTED", len(all_pages))
    log_event(inv_id, "COLLECTION_COMPLETE", f"All fanout queries finished. Total unique onion pages collected: {len(all_pages)}", "SUCCESS")

    combined_batch = {
        "batch_id": inv_id,
        "investigation_workspace": str(workspace),
        "opencode_session_id": (queue_data.get("opencode_session_id") if queue_data else batch_data.get("opencode_session_id")),
        "pages": all_pages,
        "query": (queue_data.get("original_query") if queue_data else batch_data.get("query", "darkweb_scan")),
    }

    # Deterministic Chunks for entire corpus
    consolidated_chunks: List[Dict[str, Any]] = []
    for p in all_pages:
        p_text = p.get("cleaned_text", "")
        p_url = p.get("url", "")
        p_id = hashlib.sha256(p_url.encode("utf-8")).hexdigest()[:16]
        c_list = chunk_text(p_text, page_id=p_id, url=p_url, investigation_id=inv_id)
        consolidated_chunks.extend([c.to_dict() for c in c_list])

    # Stage 2: Extractor Microservice across all pages
    update_investigation_status(inv_id, "ANALYZING")
    log_event(inv_id, "EXTRACTOR_START", "Running regex entity extraction on combined pages...", "INFO")
    extracted_data = run_extraction(combined_batch)
    log_event(inv_id, "EXTRACTOR_COMPLETE", f"Extracted {extracted_data['total_entities_found']} indicators", "SUCCESS")

    # Stage 3: Locksmith Microservice
    log_event(inv_id, "LOCKSMITH_START", "Analyzing server infrastructure & banners...", "INFO")
    locksmith_data = run_locksmith(combined_batch)
    log_event(inv_id, "LOCKSMITH_COMPLETE", f"Discovered {locksmith_data['findings_count']} infrastructure fingerprints", "SUCCESS")

    # Stage 4: Stylometry & OpSec Microservice
    log_event(inv_id, "STYLOMETRY_START", "Computing writing style vectors & OpSec leaks...", "INFO")
    stylometry_data = run_stylometry(combined_batch)
    log_event(inv_id, "STYLOMETRY_COMPLETE", f"Analyzed {stylometry_data['profiles_count']} author profiles", "SUCCESS")

    # Stage 5: Project standardized evidence workspace artifacts
    write_investigation_artifacts(
        workspace,
        all_pages,
        {"extractor": extracted_data, "locksmith": locksmith_data, "stylometry": stylometry_data},
        consolidated_chunks,
    )
    update_investigation_workspace(workspace, status="ANALYZING")
    
    # OpenCode AI Turn 2 (Attribution) & Turn 3 (Graph)
    ai_data: Dict[str, Any] = {"status": "OPENCODE_DEGRADED", "reports": [], "reports_count": 0}
    session_id = combined_batch.get("opencode_session_id")
    if session_id:
        update_investigation_status(inv_id, "OPENCODE_ANALYZING")
        update_investigation_workspace(workspace, status="OPENCODE_ANALYZING")
        log_event(inv_id, "OPENCODE_AI", "OpenCode analyzing consolidated evidence (Turn 2 Attribution)...", "INFO")
        started = start_investigation_analysis(workspace, session_id=session_id)
        if started:
            try:
                report_file = workspace / "opencode" / "attribution_report.json"
                report = wait_for_opencode_file(
                    report_file,
                    session_id,
                    timeout_seconds=TIMEOUT_TURN2_ATTRIBUTION,
                    turn_name="Turn 2: Attribution Report",
                )
                if not report:
                    final_file = workspace / "opencode" / "final_report.json"
                    report = wait_for_opencode_file(
                        final_file,
                        session_id,
                        timeout_seconds=min(5, TIMEOUT_TURN2_ATTRIBUTION),
                        turn_name="Turn 2: Final Report Fallback",
                    )

                if report:
                    ai_data = {"status": "AI_SYNTHESIZED", "reports_count": 1, "reports": [{"report": report}]}
                    from jane.backend.graph.connector import ingest_attribution_report
                    attr_result = ingest_attribution_report(inv_id=inv_id, report=report, workspace=workspace)
                    from jane.db.intelligence import persist_attribution_artifact
                    persist_attribution_artifact(inv_id, workspace, report)
                    log_event(
                        inv_id,
                        "OPENCODE_COMPLETE",
                        f"Turn 2: Synthesized evidence attribution report | Ingested {attr_result.get('actors_inserted', 0)} actors, {attr_result.get('marketplaces_inserted', 0)} markets",
                        "SUCCESS",
                    )
                else:
                    update_investigation_workspace(
                        workspace,
                        status="DEGRADED",
                        opencode_error="Turn 2 attribution report unavailable; zero actors fabricated",
                    )
                    log_event(
                        inv_id,
                        "OPENCODE_DEGRADED",
                        "Turn 2 attribution report unavailable; continuing with zero fabricated actors",
                        "WARNING",
                    )
                    ai_data = {"status": "OPENCODE_DEGRADED", "reports_count": 0, "reports": []}
            except Exception as exc:
                logger.warning(f"Evidence attribution turn error: {exc}")
                log_event(inv_id, "OPENCODE_DEGRADED", str(exc), "ERROR")

        # Turn 2.5: OSINT Target Extraction (OpenCode AI) & Maigret Clearnet Scan
        log_event(inv_id, "OSINT_START", "Extracting clearnet identity clues & launching Maigret OSINT...", "INFO")
        try:
            start_osint_extraction(workspace, session_id=session_id)
            targets_file = workspace / "osint" / "targets.json"
            wait_for_opencode_file(
                targets_file,
                session_id,
                timeout_seconds=TIMEOUT_TURN25_OSINT,
                turn_name="Turn 2.5: OSINT Targets",
            )
        except Exception as exc:
            logger.warning(f"OSINT target extraction turn error: {exc}")

        try:
            osint_summary = run_osint_enrichment(workspace, inv_id=inv_id, max_targets=3, top_sites=25)
            from jane.db.intelligence import persist_osint_artifacts
            targets_file = workspace / "osint" / "targets.json"
            persist_osint_artifacts(
                inv_id,
                workspace,
                json.loads(targets_file.read_text(encoding="utf-8")) if targets_file.exists() else {},
                osint_summary,
            )
            found_count = len(osint_summary.get("profiles_found", []))
            log_event(
                inv_id,
                "OSINT_COMPLETE",
                f"Maigret OSINT complete: Discovered {found_count} clearnet profile(s) across platforms",
                "SUCCESS",
            )
        except Exception as exc:
            logger.warning(f"OSINT execution error: {exc}")
            log_event(inv_id, "OSINT_DEGRADED", f"OSINT scan skipped: {exc}", "WARNING")

        # Turn 3: Threat Graph Synthesis
        # OpenCode writes ONLY structured JSON to graph/threat_graph.json.
        # It never writes Cytoscape config, code, or prose.
        log_event(inv_id, "GRAPH_AI_START", "OpenCode extracting threat graph (Turn 3 → graph/threat_graph.json)...", "INFO")
        start_graph_synthesis(workspace, session_id=session_id)
        threat_graph_file = workspace / "graph" / "threat_graph.json"
        threat_graph_data = wait_for_opencode_file(
            threat_graph_file,
            session_id,
            timeout_seconds=TIMEOUT_TURN3_GRAPH,
            turn_name="Turn 3: Threat Graph Synthesis",
        )
        if not threat_graph_data:
            log_event(
                inv_id,
                "GRAPH_AI_TIMEOUT",
                f"Turn 3: threat_graph.json not generated within {TIMEOUT_TURN3_GRAPH}s",
                "WARNING",
            )
    else:
        update_investigation_workspace(workspace, status="DEGRADED", opencode_error="OpenCode session unavailable")
        log_event(inv_id, "OPENCODE_DEGRADED", "OpenCode session unavailable; deterministic artifacts preserved", "ERROR")
        try:
            osint_summary = run_osint_enrichment(workspace, inv_id=inv_id, max_targets=2, top_sites=25)
            from jane.db.intelligence import persist_osint_artifacts
            targets_file = workspace / "osint" / "targets.json"
            persist_osint_artifacts(
                inv_id,
                workspace,
                json.loads(targets_file.read_text(encoding="utf-8")) if targets_file.exists() else {},
                osint_summary,
            )
        except Exception:
            pass

    # Stage 6a: Raw-evidence DB persistence (onion_pages, identifiers, threat_actors).
    # run_graph still handles saving crawl evidence rows, but no longer drives
    # graph_nodes/edges — that path is retired. Pass ai_data=None so it skips
    # the old dual-path attribution ingestion.
    log_event(inv_id, "EVIDENCE_PERSIST_START", "Persisting crawl evidence to DB (onion_pages, identifiers)...", "INFO")
    run_graph(
        inv_id=inv_id,
        batch_data=combined_batch,
        extracted_data=extracted_data,
        locksmith_data=locksmith_data,
        ai_data={"status": "EVIDENCE_ONLY", "reports": [], "reports_count": 0},
    )
    log_event(inv_id, "EVIDENCE_PERSIST_DONE", "Crawl evidence persisted.", "SUCCESS")

    # Stage 6b: Validate and ingest Turn 3's threat_graph.json as the SINGLE
    # authoritative source for graph_nodes / graph_edges. This is the only
    # code path that inserts canonical graph rows.
    log_event(inv_id, "GRAPH_INGEST_START", "Validating and ingesting threat_graph.json into graph_nodes/edges...", "INFO")
    ingest_result = ingest_threat_graph(inv_id=inv_id, workspace=workspace)
    from jane.db.intelligence import persist_threat_graph_artifact
    persist_threat_graph_artifact(inv_id, workspace)
    log_event(
        inv_id, "GRAPH_INGEST_DONE",
        f"Graph ingest: {ingest_result.get('nodes_inserted', 0)} nodes, "
        f"{ingest_result.get('edges_inserted', 0)} edges inserted | "
        f"{len(ingest_result.get('nodes_rejected', []))} nodes rejected, "
        f"{len(ingest_result.get('edges_rejected', []))} edges rejected",
        "SUCCESS" if ingest_result.get("status") == "OK" else "WARNING",
    )

    # Stage 6c: Build cytoscape.json from the now-authoritative DB summary.
    summary = get_investigation_summary(inv_id)
    cy_elements = summary.get("graph_elements", {"nodes": [], "edges": []})

    (workspace / "graph").mkdir(parents=True, exist_ok=True)
    (workspace / "graph/cytoscape.json").write_text(json.dumps(cy_elements, indent=2), encoding="utf-8")

    # Mermaid flowchart from validated DB elements — full labels, no truncation
    def _mmd_escape(s: str) -> str:
        """Escape for Mermaid quoted strings — only chars that break the parser."""
        return str(s or "").replace('"', "'").replace('\n', ' ').replace('[', '(').replace(']', ')').replace('{', '(').replace('}', ')')

    def _mmd_node_id(raw: str) -> str:
        cleaned = re.sub(r'[^a-zA-Z0-9_]', '_', str(raw))
        return ('n_' + cleaned) if (not cleaned or cleaned[0].isdigit()) else cleaned

    nodes_by_id = {n["data"]["id"]: n["data"] for n in cy_elements.get("nodes", [])}
    mermaid_defined: set = set()
    mermaid_lines = ["flowchart TD"]

    def _emit_node(nid: str, lines: list) -> str:
        mmd_id = _mmd_node_id(nid)
        if mmd_id not in mermaid_defined:
            nd = nodes_by_id.get(nid, {})
            ntype = str(nd.get("node_type", "NODE")).upper()
            # Use full_onion_url first, then url, then label — never truncate
            label = nd.get("full_onion_url") or nd.get("url") or nd.get("label") or nid
            safe_lbl = _mmd_escape(f"{ntype}: {label}")
            lines.append(f'    {mmd_id}["{safe_lbl}"]')
            mermaid_defined.add(mmd_id)
        return mmd_id

    for e in cy_elements.get("edges", []):
        ed = e.get("data", {})
        src_id = ed.get("source", "")
        tgt_id = ed.get("target", "")
        lbl = _mmd_escape(ed.get("label") or ed.get("edge_type") or "RELATED_TO")
        if not src_id or not tgt_id:
            continue
        src_mmd = _emit_node(src_id, mermaid_lines)
        tgt_mmd = _emit_node(tgt_id, mermaid_lines)
        mermaid_lines.append(f'    {src_mmd} -->|"{lbl}"| {tgt_mmd}')

    deterministic_mmd = "\n".join(mermaid_lines)
    (workspace / "graph/mermaid.deterministic.mmd").write_text(deterministic_mmd, encoding="utf-8")
    target_mmd = workspace / "graph/mermaid.mmd"

    # Turn 3.5: AI Mermaid Graph Enrichment
    enriched = False
    if session_id:
        try:
            log_event(inv_id, "MERMAID_ENRICH_START", "OpenCode synthesizing executive Mermaid map (Turn 3.5)...", "INFO")
            target_mmd.unlink(missing_ok=True)
            if start_mermaid_enrichment(workspace, session_id=session_id):
                enriched_text = wait_for_mermaid_file(target_mmd, session_id=session_id, timeout_seconds=TIMEOUT_TURN35_MERMAID)
                if enriched_text:
                    enriched = True
                    log_event(inv_id, "MERMAID_ENRICH_SUCCESS", "Turn 3.5: Executive Mermaid diagram enriched and validated", "SUCCESS")
                else:
                    log_event(inv_id, "MERMAID_FALLBACK", "Turn 3.5: Syntax check or timeout; reverted to deterministic diagram", "WARNING")
        except Exception as exc:
            logger.warning(f"Turn 3.5 Mermaid enrichment failed: {exc}")

    if not enriched:
        target_mmd.write_text(deterministic_mmd, encoding="utf-8")

    mermaid_path = paths["base"] / "investigations" / f"{inv_id}_mermaid.json"
    if mermaid_path.exists():
        (workspace / "graph/mermaid_views.json").write_text(mermaid_path.read_text(encoding="utf-8"), encoding="utf-8")

    (workspace / "graph/entities.json").write_text(json.dumps(summary.get("identifiers", []), indent=2), encoding="utf-8")
    (workspace / "graph/relationships.json").write_text(json.dumps(cy_elements.get("edges", []), indent=2), encoding="utf-8")

    update_investigation_workspace(workspace, status="COMPLETED")
    log_event(
        inv_id, "GRAPH_COMPLETE",
        f"Graph ready: {ingest_result.get('nodes_inserted', 0)} nodes, "
        f"{ingest_result.get('edges_inserted', 0)} edges from threat_graph.json",
        "SUCCESS",
    )

    # Pipeline Finish
    final_status = "COMPLETED" if ai_data.get("status") == "AI_SYNTHESIZED" else "DEGRADED"
    update_investigation_status(inv_id, final_status, len(all_pages))
    log_event(inv_id, "PIPELINE_COMPLETE", f"Investigation {inv_id} fully synthesized. Threat graph ready.", "SUCCESS")

    dest = paths["drop_processed"] / batch_path.name
    try:
        batch_path.replace(dest)
    except Exception:
        pass
    logger.info(f"[+] Investigation {inv_id} complete and stored in database.")
    return inv_id


def process_incoming_drops_once() -> List[str]:
    paths = get_paths()
    completed: List[str] = []
    incoming = list(paths["drop_incoming"].glob("batch_*.json"))
    for b in incoming:
        claimed = paths["drop_processing"] / b.name
        try:
            b.replace(claimed)
        except FileNotFoundError:
            continue
        try:
            inv_id = process_batch_file(claimed)
            if inv_id:
                completed.append(inv_id)
        except Exception as exc:
            logger.exception("Failed to process batch %s: %s", b.name, exc)
            if claimed.exists():
                claimed.replace(paths["drop_processed"] / claimed.name)
    return completed


def run_pipeline_for_query(query: str, max_onions: int = 1, max_depth: int = 1) -> str:
    """Runs complete end-to-end pipeline for a single query."""
    logger.info(f"=== Starting Jane Pipeline for query: '{query}' ===")
    inv_id = dispatch_investigation_job(query, max_onions=max_onions, max_depth=max_depth)
    
    # 1. Trigger Scout in Whonix
    trigger_whonix_scout(query, max_onions=max_onions, max_depth=max_depth, job_id=inv_id)
    
    # 2. Process incoming batch drops
    completed = process_incoming_drops_once()
    logger.info(f"=== Pipeline completed for query: '{query}' (Investigation ID: {inv_id}) ===")
    return inv_id


def run_host_worker(poll_interval: float = 2.0) -> None:
    """Continuous worker watching shared-folder drops on host."""
    logger.info("Host drop worker started; watching drop/incoming/")
    while True:
        process_incoming_drops_once()
        time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(description="Jane Pipeline Master Orchestrator")
    parser.add_argument("--query", "-q", type=str, help="Execute complete pipeline for a search query")
    parser.add_argument("--process-drops", action="store_true", help="Process any pending batches in drop/incoming/")
    args = parser.parse_args()

    init_db()

    if args.query:
        inv_id = run_pipeline_for_query(args.query)
        print(f"\n[+] Pipeline execution completed successfully for {inv_id}!")
        print(f"    View live dashboard: http://127.0.0.1:8080/dashboard.html?id={inv_id}")
    elif args.process_drops:
        done = process_incoming_drops_once()
        print(f"[+] Processed {len(done)} batch drops.")
    else:
        print("Watching for incoming batch drops... Press Ctrl+C to exit.")
        while True:
            process_incoming_drops_once()
            time.sleep(2.0)


if __name__ == "__main__":
    main()
