"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  NetworkIcon,
  SearchIcon,
  ShieldAlertIcon,
  ArrowLeftIcon,
  XIcon,
  CopyIcon,
  CheckIcon,
} from "@/components/icons";

function MaximizeIcon({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M15 3h6v6" />
      <path d="M9 21H3v-6" />
      <path d="M21 3l-7 7" />
      <path d="M3 21l7-7" />
    </svg>
  );
}

function MinimizeIcon({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M4 14h6v6" />
      <path d="M20 10h-6V4" />
      <path d="M14 10l7-7" />
      <path d="M10 14l-7 7" />
    </svg>
  );
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface NodeData {
  id: string;
  label: string;
  node_type: string;
  type?: string;
  ring?: number;
  community: number;
  degree: number;
  url?: string;
  color?: string;
  template_hash?: string;
  metadata_json?: string;
  raw_html_path?: string;
  // Canonical schema fields
  parent?: string;              // Product compound child -> parent Actor id
  handle?: string;
  role?: string;
  threat_category?: string;
  confidence?: number;
  evidence_quote?: string;
  full_onion_url?: string;
  page_urls?: string[];
  wallets?: string[];
  pgp_keys?: string[];
  known_handles?: string[];
  aliases?: string[];
  attributed_onions?: string;
  first_seen?: string;
  last_seen?: string;
  source_investigations?: string[];
  identifier_type?: string;
  full_value?: string;
  shared_by_actors?: string[];
  source_pages?: string[];
  evidence_quotes?: string[];
  category?: string;
  price?: string;
  source_page_url?: string;
}

interface EdgeData {
  id: string;
  source: string;
  target: string;
  edge_type: string;
  label?: string;
  confidence: number;
  evidence_quote?: string;
  basis?: string;
  review_status?: string;
  needs_review?: boolean;
}

interface GraphData {
  investigation: {
    id: string;
    query: string;
    status: string;
    created_at: string;
    updated_at: string;
  };
  pages: Array<{
    id: string;
    url: string;
    title?: string;
    http_status?: number;
    response_time_ms?: number;
    server_banner?: string;
    favicon_mmh3?: string;
    etag?: string;
    template_hash?: string;
    content_diff_ratio?: number;
    captured_at?: string;
    cleaned_text?: string;
    raw_html_path?: string;
  }>;
  graph_elements: {
    nodes: Array<{ data: NodeData }>;
    edges: Array<{ data: EdgeData }>;
  };
  mermaid?: string;
  mermaid_content?: string;
}

// ─── Visual constants ──────────────────────────────────────────────────────────

const NODE_COLOR: Record<string, string> = {
  // Canonical schema (threat-actor relationship graph + clearnet OSINT)
  Actor: "#1d4ed8",            // person/user silhouette — vendor handle
  Marketplace: "#4c1d95",      // storefront — distinct .onion domain/site
  Product: "#166534",          // tag — compound child nested near its Actor
  SharedIdentifier: "#92400e", // key/wallet/@ — ONLY when shared by 2+ actors
  ClearnetAccount: "#06b6d4",  // cyan — clearnet OSINT profile (Maigret)
  clearnet_account: "#06b6d4", // cyan — clearnet OSINT profile

  // Legacy fallback types (pre-redesign rows, mapped by the API)
  organization: "#991b1b",
  ORGANIZATION: "#991b1b",
  person: "#1d4ed8",
  PERSON: "#1d4ed8",
  product: "#166534",
  PRODUCT: "#166534",
  website: "#4c1d95",
  WEBSITE: "#4c1d95",
  wallet: "#92400e",
  WALLET: "#92400e",
  domain: "#4c1d95",
  DOMAIN: "#4c1d95",
  evidence: "#374151",
  EVIDENCE: "#374151",
  lead: "#854d0e",
  LEAD: "#854d0e",
  THREAT_ACTOR: "#1d4ed8",
  ACTOR: "#1d4ed8",
  BITCOIN_ADDRESS: "#92400e",
  MONERO_ADDRESS: "#92400e",
  CRYPTO: "#92400e",
  EMAIL: "#3b82f6",
  IP_ADDRESS: "#a855f7",
  LEAKED_IP: "#ec4899",
  ONION_PAGE: "#4c1d95",
  PAGE: "#4c1d95",
  FAVICON_MMH3: "#22c55e",
  INFRASTRUCTURE: "#22c55e",
  COMMS: "#c084fc",
};
const DEFAULT_COLOR = "#64748b";

const EDGE_COLOR: Record<string, string> = {
  // Canonical 4-edge schema. SHARES_IDENTIFIER is the cross-marketplace
  // correlation proof — rendered thicker and in rose, distinct from the rest.
  OPERATES_ON: "#8b5cf6",
  SELLS: "#16a34a",
  SHARES_IDENTIFIER: "#f43f5e",
  TRUST: "#f59e0b",

  "CONNECTED TO": "#ef4444",
  USES: "#f59e0b",
  "HOSTED ON": "#8b5cf6",
  "SUPPORTED BY": "#3b82f6",
  "GENERATES LEAD": "#eab308",

  // Legacy fallback edge types
  ATTRIBUTED_TO: "#ef4444",
  RECEIVED_FUNDS: "#eab308",
  CONTACTED_VIA: "#3b82f6",
  SAME_TEMPLATE: "#06b6d4",
  CO_OCCURS_WITH: "#94a3b8",
  MENTIONED_IN: "#a78bfa",
  OBSERVED_ON: "#f97316",
};
const DEFAULT_EDGE_COLOR = "#475569";

function nodeColor(type: string): string {
  return NODE_COLOR[type] ?? DEFAULT_COLOR;
}
function edgeColor(type: string): string {
  return EDGE_COLOR[type] ?? DEFAULT_EDGE_COLOR;
}

// ─── Mermaid view (client-side only) ─────────────────────────────────────────

function MermaidView({
  content,
  nodes = [],
  onSelect,
}: {
  content?: string;
  nodes?: Array<{ data: NodeData }>;
  onSelect?: (id: string | null, type: "node" | "edge", data: NodeData | EdgeData) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [scale, setScale] = useState(1);
  const [pos, setPos] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0, posX: 0, posY: 0 });
  const hasDragged = useRef(false);
  const diagramDimensions = useRef<{ w: number; h: number }>({ w: 1200, h: 800 });

  useEffect(() => {
    if (!content) return;
    let active = true;
    import("mermaid").then(({ default: mermaid }) => {
      try {
        mermaid.initialize({
          startOnLoad: false,
          theme: "dark",
          securityLevel: "loose",
          flowchart: {
            useMaxWidth: false,
            htmlLabels: true,
            curve: "basis",
          },
        });
        const renderId = `mermaid-${Math.random().toString(36).slice(2, 9)}`;
        mermaid
          .render(renderId, content)
          .then((res) => {
            if (active) {
              let cleanSvg = res.svg;
              const vb = res.svg.match(/viewBox=["']\s*([0-9.-]+)\s+([0-9.-]+)\s+([0-9.-]+)\s+([0-9.-]+)\s*["']/);
              if (vb) {
                const [, , , w, h] = vb;
                const wNum = Math.round(Number(w));
                const hNum = Math.round(Number(h));
                diagramDimensions.current = { w: wNum, h: hNum };
                cleanSvg = cleanSvg
                  .replace(/width=["']100%["']/, `width="${wNum}"`)
                  .replace(/style=["'][^"']*["']/, `style="width:${wNum}px; height:${hNum}px; min-width:${wNum}px; max-width:none;"`);
              }
              setSvg(cleanSvg);
              setError(null);
            }
          })
          .catch((err) => {
            if (active) {
              console.error("Mermaid render error:", err);
              setError(String(err?.message || err));
            }
          });
      } catch (e: any) {
        if (active) setError(String(e?.message || e));
      }
    });
    return () => {
      active = false;
    };
  }, [content]);

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.2 : 0.8;
    setScale((prev) => Math.min(Math.max(0.05, prev * factor), 15));
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    hasDragged.current = false;
    setIsDragging(true);
    dragStart.current = { x: e.clientX, y: e.clientY, posX: pos.x, posY: pos.y };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    const dx = Math.abs(e.clientX - dragStart.current.x);
    const dy = Math.abs(e.clientY - dragStart.current.y);
    if (dx > 4 || dy > 4) {
      hasDragged.current = true;
    }
    setPos({
      x: dragStart.current.posX + (e.clientX - dragStart.current.x),
      y: dragStart.current.posY + (e.clientY - dragStart.current.y),
    });
  };

  const handleMouseUp = (e: React.MouseEvent) => {
    setIsDragging(false);
    // If not a drag, check if user clicked on a diagram card/node
    if (!hasDragged.current) {
      const target = e.target as HTMLElement;
      const nodeEl = target.closest(".node");
      if (nodeEl) {
        const label =
          nodeEl.querySelector(".nodeLabel")?.textContent?.trim() ||
          nodeEl.textContent?.trim() ||
          "";
        const rawId = nodeEl.id || "";
        const idMatch = rawId.match(/flowchart-([a-zA-Z0-9_-]+?)(?:-\d+)?$/);
        const extractedId = idMatch ? idMatch[1] : rawId;

        const cleanLabel = label.replace(/^[A-Z\s_-]+:\s*/i, "").trim().toLowerCase();
        const matched = nodes.find((n) => {
          const nid = n.data.id.toLowerCase();
          const nlabel = n.data.label.toLowerCase();
          return (
            nid === extractedId.toLowerCase() ||
            nlabel === cleanLabel ||
            (cleanLabel && nlabel.includes(cleanLabel)) ||
            (cleanLabel && cleanLabel.includes(nlabel))
          );
        });

        const typeMatch = label.match(/^([A-Z\s_-]+):/);
        const cleanType = typeMatch ? typeMatch[1].trim() : "Actor";
        const displayName = label.replace(/^[A-Z\s_-]+:\s*/i, "").trim();

        const targetNodeData: NodeData = matched?.data || {
          id: extractedId,
          label: displayName || label,
          node_type: cleanType,
          community: 1,
          degree: 1,
        };

        if (onSelect) {
          onSelect(targetNodeData.id, "node", targetNodeData);
        }
      }
    }
  };

  const resetToActualSize = () => {
    setScale(1);
    setPos({ x: 0, y: 0 });
  };

  const fitToView = () => {
    if (!wrapperRef.current) return;
    const { clientWidth, clientHeight } = wrapperRef.current;
    const { w, h } = diagramDimensions.current;
    if (w > 0 && h > 0) {
      const scaleX = (clientWidth - 40) / w;
      const scaleY = (clientHeight - 40) / h;
      const fitScale = Math.min(scaleX, scaleY, 1.2);
      setScale(Math.max(0.1, Number(fitScale.toFixed(2))));
      setPos({ x: 0, y: 0 });
    }
  };

  if (!content) {
    return (
      <div className="flex h-full flex-col items-center justify-center p-6 text-muted-foreground text-sm">
        <p>No Mermaid diagram generated for this investigation.</p>
        <p className="text-xs text-muted-foreground/60 mt-1">Switch to Force or Rings layout above.</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex h-full flex-col items-center justify-center p-6 text-red-400 text-xs">
        <p className="font-semibold mb-2">Mermaid Diagram Error</p>
        <pre className="max-w-xl overflow-auto rounded bg-zinc-900/80 p-3 font-mono text-[11px] text-zinc-300">
          {content}
        </pre>
      </div>
    );
  }

  return (
    <div
      ref={wrapperRef}
      className="relative h-full w-full overflow-hidden bg-zinc-950 rounded-xl select-none cursor-grab active:cursor-grabbing"
      onWheel={handleWheel}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={() => setIsDragging(false)}
    >
      {/* Zoom / Pan Floating Controls */}
      <div className="absolute bottom-4 right-4 z-10 flex items-center gap-1 rounded-lg border border-border/60 bg-zinc-900/90 px-2.5 py-1.5 shadow-lg backdrop-blur text-xs font-mono text-foreground">
        <button
          onClick={() => setScale((s) => Math.max(0.05, s * 0.8))}
          className="h-6 w-6 rounded hover:bg-zinc-800 flex items-center justify-center text-sm"
          title="Zoom Out"
        >
          −
        </button>
        <span className="w-14 text-center text-[11px] text-muted-foreground font-semibold">
          {Math.round(scale * 100)}%
        </span>
        <button
          onClick={() => setScale((s) => Math.min(15, s * 1.25))}
          className="h-6 w-6 rounded hover:bg-zinc-800 flex items-center justify-center text-sm"
          title="Zoom In"
        >
          +
        </button>
        <div className="h-3 w-px bg-border/40 mx-1" />
        <button
          onClick={fitToView}
          className="px-2 py-0.5 rounded hover:bg-zinc-800 text-muted-foreground hover:text-foreground text-[10px]"
          title="Fit diagram to viewport"
        >
          Fit
        </button>
        <button
          onClick={resetToActualSize}
          className="px-2 py-0.5 rounded hover:bg-zinc-800 text-muted-foreground hover:text-foreground text-[10px]"
          title="Reset to 100% natural resolution"
        >
          100%
        </button>
      </div>

      <div
        className="absolute inset-0 flex items-center justify-center transition-transform duration-75 origin-center pointer-events-none"
        style={{
          transform: `translate(${pos.x}px, ${pos.y}px) scale(${scale})`,
        }}
      >
        <div
          ref={containerRef}
          className="shrink-0 pointer-events-auto [&_svg]:max-w-none [&_svg]:block [&_.node]:cursor-pointer [&_.node]:transition-all [&_.node:hover]:filter [&_.node:hover]:brightness-125"
          dangerouslySetInnerHTML={{ __html: svg }}
        />
      </div>
    </div>
  );
}

// ─── Cytoscape canvas (client-side only) ──────────────────────────────────────

interface CytoscapeCanvasProps {
  nodes: Array<{ data: NodeData }>;
  edges: Array<{ data: EdgeData }>;
  confidenceMin: number;
  evidenceOnly: boolean;
  nodeTypeFilter: string[];
  communityFilter: number | null;
  searchTerm: string;
  selectedId: string | null;
  layoutMode: "mermaid" | "cose" | "concentric";
  isExpanded?: boolean;
  onSelect: (id: string | null, type: "node" | "edge", data: NodeData | EdgeData) => void;
}

function CytoscapeCanvas({
  nodes,
  edges,
  confidenceMin,
  evidenceOnly,
  nodeTypeFilter,
  communityFilter,
  searchTerm,
  selectedId,
  layoutMode,
  isExpanded = false,
  onSelect,
}: CytoscapeCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<any>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    let cy: any;

    import("cytoscape").then(({ default: Cytoscape }) => {
      // Filter
      const visibleNodeIds = new Set(
        nodes
          .filter((n) => {
            const rawType = n.data.type || n.data.node_type || "";
            if (nodeTypeFilter.length > 0 && !nodeTypeFilter.includes(rawType) && !nodeTypeFilter.includes(n.data.node_type)) return false;
            if (communityFilter !== null && n.data.community !== communityFilter) return false;
            if (searchTerm && !n.data.label.toLowerCase().includes(searchTerm.toLowerCase()) && !n.data.id.toLowerCase().includes(searchTerm.toLowerCase())) return false;
            return true;
          })
          .map((n) => n.data.id)
      );

      const visibleEdges = edges.filter((e) => {
        if (!visibleNodeIds.has(e.data.source) || !visibleNodeIds.has(e.data.target)) return false;
        if (e.data.confidence < confidenceMin) return false;
        if (evidenceOnly && (!e.data.evidence_quote || e.data.confidence < 0.80)) return false;
        return true;
      });

      const elements = [
        ...Array.from(visibleNodeIds).map((id) => {
          const n = nodes.find((n) => n.data.id === id)!;
          const rawType = n.data.type || n.data.node_type || "";
          const entityType = ["Actor", "Marketplace", "Product", "SharedIdentifier"].includes(rawType)
            ? rawType
            : (rawType || "").toLowerCase();
          const ring = n.data.ring ?? 2;

          // Product nodes render as small attached boxes (compound children
          // nested near their parent Actor, not floating independently).
          const isProduct = entityType === "Product";
          let size = Math.max(24, Math.min(64, 24 + (n.data.degree || 1) * 4));
          if (entityType === "Actor") size = 75;
          else if (entityType === "Marketplace") size = 70;
          else if (isProduct) size = 40;
          else if (entityType === "SharedIdentifier") size = 58;

          const el: any = {
            group: "nodes" as const,
            data: {
              // Fall back to the marketplace's first page / product source
              // page so the "Source Page / View Raw HTML" tab keeps working.
              url: (n.data as any).url || ((n.data as any).page_urls || [])[0] || (n.data as any).source_page_url,
              ...n.data,
              ring,
              entityType,
              size,
              nodeColor: nodeColor(n.data.type || n.data.node_type),
            },
          };
          // Cytoscape compound support: Product stays grouped with its Actor.
          if (isProduct && n.data.parent && visibleNodeIds.has(n.data.parent)) {
            el.data.parent = n.data.parent;
          }
          return el;
        }),
        ...visibleEdges.map((e) => {
          const edgeType = e.data.edge_type || "";
          const displayLabel =
            edgeType === "OPERATES_ON" ? "operates on"
            : edgeType === "SELLS" ? "sells"
            : edgeType === "TRUST" ? "vouched by"
            : (e.data.label || edgeType || "");
          // SHARES_IDENTIFIER is the correlation proof: thicker, rose.
          const isShares = edgeType === "SHARES_IDENTIFIER";
          return {
            group: "edges" as const,
            data: {
              ...e.data,
              displayLabel,
              width: isShares
                ? Math.max(3.5, (e.data.confidence || 0.8) * 6)
                : Math.max(1.5, (e.data.confidence || 0.8) * 4),
              edgeColor: edgeColor(edgeType),
              opacity: 0.5 + (e.data.confidence || 0.8) * 0.5,
            },
          };
        }),
      ];

      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }

      const layoutConfig = layoutMode === "cose"
        ? {
            name: "cose",
            idealEdgeLength: 90,
            nodeRepulsion: 8000,
            animate: false,
            fit: true,
            padding: 30,
          }
        : {
            name: "concentric",
            concentric: (node: any) => {
              const ring = Number(node.data("ring")) || 2;
              // Ring 1 (Center) -> returns 3 (highest level)
              // Ring 2 (Middle) -> returns 2
              // Ring 3 (Outer)  -> returns 1 (lowest level)
              if (ring === 1) return 3;
              if (ring === 2) return 2;
              return 1;
            },
            levelWidth: () => 1,
            animate: false,
            fit: true,
            padding: 50,
            minNodeSpacing: 45,
          };

      cy = Cytoscape({
        container: containerRef.current,
        elements,
        style: [
          {
            selector: "node",
            style: {
              "background-color": "data(nodeColor)",
              "label": "data(label)",
              "color": "#f1f5f9",
              "font-size": 10,
              "font-family": "monospace",
              "text-valign": "bottom",
              "text-margin-y": 4,
              "width": "data(size)",
              "height": "data(size)",
              "border-width": 2,
              "border-color": "#334155",
              "text-background-color": "#09090b",
              "text-background-opacity": 0.8,
              "text-background-padding": "3px",
              "text-background-shape": "roundrectangle",
              "text-max-width": 120,
              "text-wrap": "ellipsis",
            } as any,
          },
          {
            selector: 'node[entityType = "Actor"]',
            style: {
              "background-color": "#1d4ed8",
              "border-color": "#3b82f6",
              "border-width": 2,
              "shape": "ellipse",
            } as any,
          },
          {
            selector: 'node[entityType = "Marketplace"]',
            style: {
              "background-color": "#4c1d95",
              "border-color": "#a855f7",
              "border-width": 2,
              "shape": "round-rectangle",
            } as any,
          },
          {
            selector: 'node[entityType = "Product"]',
            style: {
              "background-color": "#166534",
              "border-color": "#22c55e",
              "border-width": 2,
              "shape": "rectangle",
              "font-size": 8,
            } as any,
          },
          {
            selector: 'node[entityType = "SharedIdentifier"]',
            style: {
              "background-color": "#92400e",
              "border-color": "#f43f5e",
              "border-width": 3,
              "shape": "diamond",
            } as any,
          },
          {
            // Compound parent shells (Actors grouping their Products)
            selector: ":parent",
            style: {
              "background-color": "#0f172a",
              "background-opacity": 0.45,
              "border-color": "#334155",
              "border-width": 1.5,
              "border-style": "dashed",
              "text-valign": "top",
              "text-halign": "center",
            } as any,
          },
          {
            selector: 'node[entityType = "lead"]',
            style: {
              "background-color": "#854d0e",
              "border-color": "#eab308",
              "border-width": 2.5,
              "shape": "round-rectangle",
            } as any,
          },
          {
            selector: "node:selected",
            style: {
              "border-color": "#38bdf8",
              "border-width": 3.5,
            },
          },
          {
            selector: "edge",
            style: {
              "width": "data(width)",
              "line-color": "data(edgeColor)",
              "target-arrow-color": "data(edgeColor)",
              "target-arrow-shape": "triangle",
              "curve-style": "bezier",
              "opacity": "data(opacity)",
              "label": "data(displayLabel)",
              "font-size": 8,
              "font-family": "monospace",
              "color": "#cbd5e1",
              "text-background-color": "#09090b",
              "text-background-opacity": 0.85,
              "text-background-padding": "2px",
              "text-background-shape": "roundrectangle",
              "edge-text-rotation": "autorotate",
            } as any,
          },
          {
            selector: "edge:selected",
            style: { "line-color": "#38bdf8", "target-arrow-color": "#38bdf8", opacity: 1 },
          },
          {
            // SHARES_IDENTIFIER: the cross-marketplace correlation proof.
            selector: 'edge[edge_type = "SHARES_IDENTIFIER"]',
            style: {
              "line-color": "#f43f5e",
              "target-arrow-color": "#f43f5e",
              "width": 4,
              "opacity": 0.95,
              "line-style": "solid",
            } as any,
          },
          {
            selector: 'edge[edge_type = "TRUST"]',
            style: {
              "line-color": "#f59e0b",
              "target-arrow-color": "#f59e0b",
              "line-style": "dashed",
            } as any,
          },
        ],
        layout: layoutConfig as any,
        boxSelectionEnabled: false,
        autounselectify: false,
        userZoomingEnabled: true,
        userPanningEnabled: true,
      });

      cy.on("tap", "node", (evt: any) => {
        onSelect(evt.target.id(), "node", evt.target.data());
      });
      cy.on("tap", "edge", (evt: any) => {
        onSelect(evt.target.id(), "edge", evt.target.data());
      });
      cy.on("tap", (evt: any) => {
        if (evt.target === cy) onSelect(null, "node", {} as any);
      });

      cyRef.current = cy;
    });

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [nodes, edges, confidenceMin, evidenceOnly, nodeTypeFilter, communityFilter, searchTerm, layoutMode]);

  // Highlight selected
  useEffect(() => {
    if (!cyRef.current) return;
    if (selectedId) {
      const el = cyRef.current.getElementById(selectedId);
      if (el.length) { el.select(); cyRef.current.center(el); }
    }
  }, [selectedId]);

  // Resize when height expanded/collapsed
  useEffect(() => {
    if (!cyRef.current) return;
    const timer = setTimeout(() => {
      cyRef.current?.resize();
      cyRef.current?.fit(undefined, 35);
    }, 200);
    return () => clearTimeout(timer);
  }, [isExpanded]);

  return <div ref={containerRef} className="h-full w-full bg-zinc-950 rounded-xl" />;
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function GraphWorkspacePage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [data, setData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);

  // Canvas filters
  const [confidenceMin, setConfidenceMin] = useState(0);
  const [evidenceOnly, setEvidenceOnly] = useState(false);
  const [nodeTypeFilter, setNodeTypeFilter] = useState<string[]>([]);
  const [communityFilter, setCommunityFilter] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [hideIsolated, setHideIsolated] = useState(false);
  const [layoutMode, setLayoutMode] = useState<"mermaid" | "cose" | "concentric">("mermaid");
  const [isExpanded, setIsExpanded] = useState(false);

  // Selection
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedType, setSelectedType] = useState<"node" | "edge">("node");
  const [selectedData, setSelectedData] = useState<NodeData | EdgeData | null>(null);

  // Evidence drawer
  const [drawerTab, setDrawerTab] = useState<"quote" | "text" | "html" | "headers" | "meta">("quote");
  const [pageHtml, setPageHtml] = useState<string>("");
  const [htmlLoading, setHtmlLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!id) return;
    if (typeof window !== "undefined") {
      const q = new URLSearchParams(window.location.search).get("search");
      if (q) {
        setSearchTerm(q);
        setLayoutMode("cose");
      }
    }
    fetch(`/api/graph/investigation?id=${id}`)
      .then((r) => r.json())
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [id]);

  const nodes = data?.graph_elements?.nodes ?? [];
  const edges = data?.graph_elements?.edges ?? [];

  // Derived stats
  const nodeTypes = useMemo(() => [...new Set(nodes.map((n) => n.data.node_type))].sort(), [nodes]);
  const communities = useMemo(() => [...new Set(nodes.map((n) => n.data.community).filter(Boolean))].sort((a, b) => a - b), [nodes]);

  // Degree map for betweenness approximation
  const degreeMap = useMemo(() => {
    const m: Record<string, number> = {};
    edges.forEach((e) => {
      m[e.data.source] = (m[e.data.source] || 0) + 1;
      m[e.data.target] = (m[e.data.target] || 0) + 1;
    });
    return m;
  }, [edges]);

  // Top pivots: confidence-weighted degree
  const topPivots = useMemo(() => {
    const confByNode: Record<string, number> = {};
    edges.forEach((e) => {
      confByNode[e.data.source] = (confByNode[e.data.source] || 0) + e.data.confidence;
      confByNode[e.data.target] = (confByNode[e.data.target] || 0) + e.data.confidence;
    });
    return [...nodes]
      .map((n) => ({ ...n.data, score: confByNode[n.data.id] || 0 }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 6);
  }, [nodes, edges]);

  // Bridge nodes: nodes whose degree connects multiple communities
  const bridgeNodes = useMemo(() => {
    const communityEdges: Record<string, Set<number>> = {};
    const nodeComm = Object.fromEntries(nodes.map((n) => [n.data.id, n.data.community]));
    edges.forEach((e) => {
      const sc = nodeComm[e.data.source];
      const tc = nodeComm[e.data.target];
      if (sc && tc && sc !== tc) {
        communityEdges[e.data.source] = (communityEdges[e.data.source] || new Set()).add(tc);
        communityEdges[e.data.target] = (communityEdges[e.data.target] || new Set()).add(sc);
      }
    });
    return [...nodes]
      .filter((n) => communityEdges[n.data.id]?.size >= 1)
      .sort((a, b) => (degreeMap[b.data.id] || 0) - (degreeMap[a.data.id] || 0))
      .slice(0, 5);
  }, [nodes, edges, degreeMap]);

  // Cross-onion shared IOCs
  const crossOnionIOCs = useMemo(() => {
    // SharedIdentifier nodes connected to multiple marketplaces
    const onionNodes = new Set(nodes.filter((n) => ["Marketplace", "ONION_PAGE", "PAGE"].includes(n.data.node_type)).map((n) => n.data.id));
    const onionsByNode: Record<string, Set<string>> = {};
    edges.forEach((e) => {
      if (onionNodes.has(e.data.target)) {
        onionsByNode[e.data.source] = (onionsByNode[e.data.source] || new Set()).add(e.data.target);
      }
      if (onionNodes.has(e.data.source)) {
        onionsByNode[e.data.target] = (onionsByNode[e.data.target] || new Set()).add(e.data.source);
      }
    });
    return [...nodes]
      .filter((n) => !onionNodes.has(n.data.id) && (onionsByNode[n.data.id]?.size ?? 0) > 1)
      .map((n) => ({ ...n.data, onion_count: onionsByNode[n.data.id]?.size ?? 0 }))
      .sort((a, b) => b.onion_count - a.onion_count)
      .slice(0, 8);
  }, [nodes, edges]);

  // Community table
  const communityTable = useMemo(() => {
    const cm: Record<number, {
      actors: number; onions: number; wallets: number; comms: number;
      highConfEdges: number; dominantEdge: Record<string, number>; maxDeg: { label: string; deg: number };
      sanctioned: number;
    }> = {};
    nodes.forEach((n) => {
      const c = n.data.community ?? 0;
      if (!cm[c]) cm[c] = { actors: 0, onions: 0, wallets: 0, comms: 0, highConfEdges: 0, dominantEdge: {}, maxDeg: { label: "", deg: 0 }, sanctioned: 0 };
      const t = n.data.node_type;
      if (["Actor", "ACTOR", "THREAT_ACTOR"].includes(t)) cm[c].actors++;
      else if (["Marketplace", "ONION_PAGE", "PAGE"].includes(t)) cm[c].onions++;
      else if (["SharedIdentifier", "BITCOIN_ADDRESS", "MONERO_ADDRESS", "CRYPTO"].includes(t)) cm[c].wallets++;
      else if (["EMAIL", "COMMS"].includes(t)) cm[c].comms++;
      const deg = degreeMap[n.data.id] || 0;
      if (deg > cm[c].maxDeg.deg) cm[c].maxDeg = { label: n.data.label, deg };
      // Sanctioned from metadata
      try { const m = JSON.parse(n.data.metadata_json || "{}"); if (m.is_sanctioned) cm[c].sanctioned++; } catch {}
    });
    edges.forEach((e) => {
      const srcComm = nodes.find((n) => n.data.id === e.data.source)?.data.community;
      if (srcComm == null) return;
      if (e.data.confidence >= 0.80) cm[srcComm].highConfEdges++;
      cm[srcComm].dominantEdge[e.data.edge_type] = (cm[srcComm].dominantEdge[e.data.edge_type] || 0) + 1;
    });
    return Object.entries(cm).map(([c, d]) => ({
      community: Number(c),
      ...d,
      dominantRel: Object.entries(d.dominantEdge).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "—",
    })).sort((a, b) => (b.actors + b.highConfEdges) - (a.actors + a.highConfEdges));
  }, [nodes, edges, degreeMap]);

  const handleSelect = useCallback((selId: string | null, type: "node" | "edge", selData: NodeData | EdgeData) => {
    setSelectedId(selId);
    setSelectedType(type);
    setSelectedData(selId ? selData : null);
    setDrawerTab("quote");
    setPageHtml("");
  }, []);

  // Load HTML for selected node (onion page)
  const selectedNodeData = selectedType === "node" ? (selectedData as NodeData) : null;
  const selectedEdgeData = selectedType === "edge" ? (selectedData as EdgeData) : null;

  const loadHtml = useCallback((url: string) => {
    if (!url) return;
    setHtmlLoading(true);
    fetch(`/api/snapshot?url=${encodeURIComponent(url)}`)
      .then((r) => r.json())
      .then((d) => setPageHtml(d.html || d.cleaned_text || "No content available"))
      .catch(() => setPageHtml("Failed to load"))
      .finally(() => setHtmlLoading(false));
  }, []);

  // Page info for selected node
  const pageInfo = useMemo(() => {
    if (!selectedNodeData?.url) return null;
    return data?.pages?.find((p) => p.url === selectedNodeData.url) ?? null;
  }, [selectedNodeData, data?.pages]);

  // Export subgraph
  const exportSubgraph = () => {
    const visible = { nodes, edges: edges.filter((e) => e.data.confidence >= confidenceMin) };
    navigator.clipboard.writeText(JSON.stringify(visible, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleNodeType = (t: string) =>
    setNodeTypeFilter((prev) => prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]);

  const inv = data?.investigation;
  const highConfEdges = edges.filter((e) => e.data.confidence >= 0.80).length;
  const commCount = new Set(nodes.map((n) => n.data.community)).size;

  return (
    <AppShell>
      <div className="flex h-full flex-col overflow-hidden">
        {/* ── Top bar ── */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/40 bg-zinc-950/90 px-4 py-2.5">
          <div className="flex items-center gap-3">
            <Button size="sm" variant="ghost" className="h-7 gap-1 text-xs text-muted-foreground" onClick={() => router.push("/graph")}>
              <ArrowLeftIcon className="h-3.5 w-3.5" /> Graph Investigations
            </Button>
            <div className="h-4 w-px bg-border/40" />
            <div className="flex items-center gap-2">
              <span className="font-semibold text-sm text-foreground">{inv?.query ?? id}</span>
              <Badge variant="outline" className="font-mono text-[10px]">{inv?.status}</Badge>
              <span className="font-mono text-[10px] text-muted-foreground">{id}</span>
            </div>
          </div>
          <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
            <span className="font-mono"><strong className="text-foreground">{nodes.length}</strong> nodes</span>
            <span className="font-mono"><strong className="text-emerald-400">{highConfEdges}</strong> strong edges</span>
            <span className="font-mono"><strong className="text-amber-400">{commCount}</strong> clusters</span>
            <Button size="sm" variant="outline" className="h-7 gap-1 text-xs" onClick={exportSubgraph}>
              {copied ? <CheckIcon className="h-3.5 w-3.5 text-emerald-400" /> : <CopyIcon className="h-3.5 w-3.5" />}
              {copied ? "Copied!" : "Export Subgraph"}
            </Button>
          </div>
        </div>

        {/* ── Filter bar ── */}
        <div className="flex flex-wrap items-center gap-2 border-b border-border/30 bg-zinc-950/60 px-4 py-2">
          <div className="flex items-center gap-1.5">
            <SearchIcon className="h-3.5 w-3.5 text-muted-foreground" />
            <Input placeholder="Search node / IOC…" value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)}
              className="h-7 w-40 text-xs font-mono" />
          </div>
          <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <span>Confidence ≥</span>
            <input type="range" min={0} max={1} step={0.05} value={confidenceMin}
              onChange={(e) => setConfidenceMin(Number(e.target.value))}
              className="w-24 accent-primary" />
            <span className="font-mono w-8">{(confidenceMin * 100).toFixed(0)}%</span>
          </div>
          {[
            ["Evidence-backed only", evidenceOnly, () => setEvidenceOnly(!evidenceOnly)],
            ["Hide isolated", hideIsolated, () => setHideIsolated(!hideIsolated)],
          ].map(([label, active, toggle]) => (
            <button key={label as string}
              onClick={toggle as () => void}
              className={`rounded border px-2 py-0.5 text-[11px] transition-colors ${active ? "border-primary/60 bg-primary/10 text-primary" : "border-border/40 text-muted-foreground hover:border-border"}`}>
              {label as string}
            </button>
          ))}
          <div className="flex flex-wrap gap-1">
            {nodeTypes.map((t) => (
              <button key={t}
                onClick={() => toggleNodeType(t)}
                style={{ borderColor: nodeColor(t) + "60", color: nodeTypeFilter.length === 0 || nodeTypeFilter.includes(t) ? nodeColor(t) : "#64748b" }}
                className="rounded border px-2 py-0.5 text-[10px] font-mono transition-colors hover:opacity-80">
                {t}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <span>Cluster:</span>
            <select value={communityFilter ?? ""} onChange={(e) => setCommunityFilter(e.target.value === "" ? null : Number(e.target.value))}
              className="h-7 rounded border border-border/40 bg-transparent px-2 text-[11px] font-mono">
              <option value="">All</option>
              {communities.map((c) => <option key={c} value={c}>#{c}</option>)}
            </select>
          </div>

          <div className="flex items-center gap-1 rounded border border-border/40 p-0.5 bg-zinc-900/50">
            <button
              onClick={() => setLayoutMode("mermaid")}
              className={`rounded px-2 py-0.5 text-[11px] font-mono transition-colors ${
                layoutMode === "mermaid"
                  ? "bg-primary/20 text-primary border border-primary/40"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              ◈ Mermaid
            </button>
            <button
              onClick={() => setLayoutMode("cose")}
              className={`rounded px-2 py-0.5 text-[11px] font-mono transition-colors ${
                layoutMode === "cose"
                  ? "bg-primary/20 text-primary border border-primary/40"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              ☊ Force
            </button>
            <button
              onClick={() => setLayoutMode("concentric")}
              className={`rounded px-2 py-0.5 text-[11px] font-mono transition-colors ${
                layoutMode === "concentric"
                  ? "bg-primary/20 text-primary border border-primary/40"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              ◎ Rings
            </button>
          </div>

          <button onClick={() => { setSearchTerm(""); setConfidenceMin(0); setEvidenceOnly(false); setNodeTypeFilter([]); setCommunityFilter(null); setHideIsolated(false); setLayoutMode("cose"); }}
            className="ml-auto rounded border border-border/40 px-2 py-0.5 text-[11px] text-muted-foreground hover:border-border">
            Reset filters
          </button>
        </div>

        {/* ── Main workspace ── */}
        <div className={`flex overflow-hidden transition-all duration-300 ${isExpanded ? "flex-1 min-h-[75vh]" : "flex-1"}`}>
          {/* Cytoscape canvas */}
          <div className="flex-1 overflow-hidden p-3 relative">
            {/* Expand / Maximize height icon button */}
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              title={isExpanded ? "Collapse to standard height" : "Expand canvas height"}
              className="absolute top-5 right-5 z-20 flex items-center gap-1.5 rounded-md border border-border/60 bg-zinc-900/90 px-2.5 py-1 text-xs text-foreground shadow-md backdrop-blur hover:bg-zinc-800 hover:border-primary/50 transition-all cursor-pointer"
            >
              {isExpanded ? (
                <>
                  <MinimizeIcon className="h-3.5 w-3.5 text-primary" />
                  <span className="font-mono text-[10px]">Normal</span>
                </>
              ) : (
                <>
                  <MaximizeIcon className="h-3.5 w-3.5 text-primary" />
                  <span className="font-mono text-[10px]">Expand</span>
                </>
              )}
            </button>

            {loading ? (
              <div className="flex h-full items-center justify-center text-muted-foreground text-sm">Loading graph…</div>
            ) : layoutMode === "mermaid" ? (
              <MermaidView
                content={data?.mermaid || data?.mermaid_content}
                nodes={nodes}
                onSelect={handleSelect}
              />
            ) : (
              <CytoscapeCanvas
                nodes={nodes}
                edges={edges}
                confidenceMin={confidenceMin}
                evidenceOnly={evidenceOnly}
                nodeTypeFilter={nodeTypeFilter}
                communityFilter={communityFilter}
                searchTerm={searchTerm}
                selectedId={selectedId}
                layoutMode={layoutMode}
                isExpanded={isExpanded}
                onSelect={handleSelect}
              />
            )}
          </div>

          {/* Right dossier panel — shown when something is selected */}
          {selectedData && (
            <div className="w-80 shrink-0 overflow-y-auto border-l border-border/40 bg-zinc-950/90 p-4 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-foreground">
                  {selectedType === "node" ? "Entity Dossier" : "Edge Evidence"}
                </span>
                <button onClick={() => { setSelectedId(null); setSelectedData(null); }}
                  className="text-muted-foreground hover:text-foreground">
                  <XIcon className="h-4 w-4" />
                </button>
              </div>

              {selectedType === "node" && selectedNodeData && (
                <>
                  {/* Node identity — all attached data for the canonical type */}
                  <div className="rounded-xl border border-border/40 bg-zinc-900/60 p-3 space-y-2">
                    <div className="flex items-center gap-2">
                      <div className="h-3 w-3 rounded-full shrink-0" style={{ backgroundColor: nodeColor(selectedNodeData.node_type) }} />
                      <span className="font-mono text-xs font-semibold text-foreground truncate">{selectedNodeData.label}</span>
                    </div>
                    <div className="grid grid-cols-2 gap-1 text-[11px]">
                      <span className="text-muted-foreground">Type</span><span className="text-foreground font-mono">{selectedNodeData.node_type}</span>
                      <span className="text-muted-foreground">Community</span><span className="text-foreground">Cluster #{selectedNodeData.community}</span>
                      <span className="text-muted-foreground">Degree</span><span className="text-foreground tabular-nums">{degreeMap[selectedNodeData.id] || selectedNodeData.degree}</span>
                      {selectedNodeData.handle && (<><span className="text-muted-foreground">Handle</span><span className="text-foreground font-mono truncate">{selectedNodeData.handle}</span></>)}
                      {selectedNodeData.role && (<><span className="text-muted-foreground">Role</span><span className="text-foreground">{selectedNodeData.role}</span></>)}
                      {selectedNodeData.threat_category && (<><span className="text-muted-foreground">Category</span><span className="text-foreground">{selectedNodeData.threat_category}</span></>)}
                      {selectedNodeData.confidence != null && (<><span className="text-muted-foreground">Confidence</span><span className="text-foreground font-mono">{(Number(selectedNodeData.confidence) * 100).toFixed(0)}%</span></>)}
                      {selectedNodeData.first_seen && (<><span className="text-muted-foreground">First seen</span><span className="text-foreground font-mono text-[10px]">{String(selectedNodeData.first_seen).slice(0, 10)}</span></>)}
                      {selectedNodeData.last_seen && (<><span className="text-muted-foreground">Last seen</span><span className="text-foreground font-mono text-[10px]">{String(selectedNodeData.last_seen).slice(0, 10)}</span></>)}
                      {selectedNodeData.full_onion_url && (<><span className="text-muted-foreground">Onion</span><span className="text-foreground font-mono text-[10px] truncate">{selectedNodeData.full_onion_url}</span></>)}
                      {selectedNodeData.identifier_type && (<><span className="text-muted-foreground">ID type</span><span className="text-foreground font-mono">{selectedNodeData.identifier_type}</span></>)}
                      {selectedNodeData.category && (<><span className="text-muted-foreground">Category</span><span className="text-foreground">{selectedNodeData.category}</span></>)}
                      {selectedNodeData.price && (<><span className="text-muted-foreground">Price</span><span className="text-foreground font-mono">{selectedNodeData.price}</span></>)}
                    </div>
                    {(() => {
                      const detectedOnion =
                        selectedNodeData.full_onion_url ||
                        (selectedNodeData.url?.includes(".onion") ? selectedNodeData.url : "") ||
                        (selectedNodeData.label?.includes(".onion") ? selectedNodeData.label.replace(/^[^:]+:\s*/, "") : "") ||
                        (selectedNodeData.id?.includes(".onion") ? selectedNodeData.id : "");
                      if (!detectedOnion) return null;

                      const cleanDomain = detectedOnion.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
                      const matchedPage = data?.pages?.find((p) =>
                        p.url.toLowerCase().includes(cleanDomain) ||
                        cleanDomain.includes(p.url.toLowerCase().replace(/^https?:\/\//, "").split("/")[0])
                      );

                      const targetHref = matchedPage
                        ? `/onions/${matchedPage.id}`
                        : `/onions?search=${encodeURIComponent(cleanDomain)}`;

                      return (
                        <div className="pt-2 border-t border-border/30 space-y-1.5">
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="text-muted-foreground">Onion Target:</span>
                            <span className="font-mono text-[10px] text-purple-300 truncate max-w-[170px]" title={detectedOnion}>
                              {cleanDomain}
                            </span>
                          </div>
                          <Link href={targetHref} className="block group">
                            <div className="flex items-center justify-between rounded-lg border border-purple-500/40 bg-purple-950/30 px-2.5 py-1.5 text-xs text-purple-300 hover:bg-purple-900/50 hover:border-purple-400 transition-all shadow-sm">
                              <span className="flex items-center gap-1.5 font-medium text-[11px]">
                                🧅 View in Onion Explorer
                              </span>
                              <span className="text-[11px] group-hover:translate-x-0.5 transition-transform">→</span>
                            </div>
                          </Link>
                        </div>
                      );
                    })()}
                    {selectedNodeData.evidence_quote && (
                      <div className="pt-2 border-t border-border/30">
                        <span className="text-muted-foreground text-[10px] block mb-1">Evidence Quote:</span>
                        <div className="rounded bg-zinc-950 p-2 font-mono text-[10px] text-zinc-300 border border-border/30 max-h-32 overflow-y-auto whitespace-pre-wrap">
                          "{selectedNodeData.evidence_quote}"
                        </div>
                      </div>
                    )}
                    {(selectedNodeData.wallets?.length || selectedNodeData.pgp_keys?.length || selectedNodeData.known_handles?.length) ? (
                      <div className="pt-1 space-y-1 text-[10px] font-mono">
                        {(selectedNodeData.wallets || []).map((w) => <div key={w} className="truncate text-yellow-300/90">◈ {w}</div>)}
                        {(selectedNodeData.pgp_keys || []).map((k) => <div key={k} className="truncate text-emerald-300/90">🔑 {String(k).slice(0, 48)}</div>)}
                        {(selectedNodeData.known_handles || []).map((h) => <div key={h} className="truncate text-purple-300/90">@{h}</div>)}
                      </div>
                    ) : null}
                    {selectedNodeData.full_value && (
                      <div className="pt-1 font-mono text-[10px] text-amber-200 break-all">{selectedNodeData.full_value}</div>
                    )}
                    {selectedNodeData.shared_by_actors?.length ? (
                      <div className="pt-1 text-[10px] text-muted-foreground">Shared by: <span className="text-foreground font-mono">{selectedNodeData.shared_by_actors.join(", ")}</span></div>
                    ) : null}
                    {selectedNodeData.source_investigations?.length ? (
                      <div className="pt-1 text-[10px] text-muted-foreground">Investigations: <span className="text-foreground font-mono">{selectedNodeData.source_investigations.join(", ")}</span></div>
                    ) : null}
                  </div>

                  {/* Connected edges — backlinks included, both directions */}
                  <div>
                    <div className="mb-2 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">Connections</div>
                    <div className="space-y-1.5">
                      {edges.filter((e) => e.data.source === selectedNodeData.id || e.data.target === selectedNodeData.id)
                        .sort((a, b) => b.data.confidence - a.data.confidence)
                        .slice(0, 12)
                        .map((e) => (
                          <div key={e.data.id} onClick={() => handleSelect(e.data.id, "edge", e.data)}
                            className="cursor-pointer rounded-lg border border-border/30 bg-zinc-900/40 p-2 hover:bg-zinc-900 transition-colors">
                            <div className="flex items-center justify-between gap-1">
                              <span className="font-mono text-[10px]" style={{ color: edgeColor(e.data.edge_type) }}>{e.data.edge_type}</span>
                              <span className="flex items-center gap-1">
                                {e.data.needs_review && <Badge variant="outline" className="text-[9px] font-mono text-amber-400 border-amber-500/40">needs review</Badge>}
                                <Badge variant="outline" className="text-[9px] font-mono">{(e.data.confidence * 100).toFixed(0)}%</Badge>
                              </span>
                            </div>
                            <div className="mt-0.5 truncate font-mono text-[9px] text-muted-foreground">
                              {e.data.source === selectedNodeData.id ? `→ ${e.data.target.slice(0, 40)}` : `← ${e.data.source.slice(0, 40)}`}
                            </div>
                            {e.data.evidence_quote && (
                              <div className="mt-1 font-mono text-[9px] italic text-emerald-300/80 truncate">“{e.data.evidence_quote.slice(0, 90)}”</div>
                            )}
                          </div>
                        ))}
                    </div>
                  </div>

                  {/* Page preview tabs */}
                  {selectedNodeData.url && (
                    <div>
                      <div className="mb-2 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">Source Page</div>
                      <div className="flex gap-1 mb-2 flex-wrap">
                        {(["quote", "text", "html", "headers", "meta"] as const).map((t) => (
                          <button key={t} onClick={() => { setDrawerTab(t); if (t === "html" || t === "text") loadHtml(selectedNodeData.url!); }}
                            className={`rounded px-2 py-0.5 text-[10px] transition-colors ${drawerTab === t ? "bg-primary/20 text-primary border border-primary/40" : "border border-border/30 text-muted-foreground hover:border-border"}`}>
                            {t === "quote" ? "Evidence" : t === "text" ? "Cleaned Text" : t === "html" ? "Raw HTML" : t === "headers" ? "Headers" : "Capture Metadata"}
                          </button>
                        ))}
                      </div>
                      <div className="rounded-xl border border-border/30 bg-zinc-900/40 p-3 text-[11px] text-muted-foreground max-h-60 overflow-y-auto">
                        {drawerTab === "quote" && <p className="text-muted-foreground italic">Click an edge to see evidence quotes.</p>}
                        {drawerTab === "text" && (htmlLoading ? "Loading…" : <pre className="whitespace-pre-wrap break-all font-mono text-[10px]">{pageHtml.slice(0, 2000)}</pre>)}
                        {drawerTab === "html" && (htmlLoading ? "Loading…" : <pre className="whitespace-pre-wrap break-all font-mono text-[10px] text-green-300">{pageHtml.slice(0, 3000)}</pre>)}
                        {drawerTab === "headers" && pageInfo && (
                          <div className="space-y-1 font-mono text-[10px]">
                            <div><span className="text-muted-foreground">HTTP Status:</span> <span className="text-foreground">{pageInfo.http_status}</span></div>
                            <div><span className="text-muted-foreground">Server:</span> <span className="text-foreground">{pageInfo.server_banner || "—"}</span></div>
                            <div><span className="text-muted-foreground">ETag:</span> <span className="text-foreground">{pageInfo.etag || "—"}</span></div>
                            <div><span className="text-muted-foreground">Favicon mmh3:</span> <span className="text-foreground">{pageInfo.favicon_mmh3 || "—"}</span></div>
                            <div><span className="text-muted-foreground">Response time:</span> <span className="text-foreground">{pageInfo.response_time_ms}ms</span></div>
                          </div>
                        )}
                        {drawerTab === "meta" && pageInfo && (
                          <div className="space-y-1 font-mono text-[10px]">
                            <div><span className="text-muted-foreground">Captured:</span> <span className="text-foreground">{pageInfo.captured_at || "—"}</span></div>
                            <div><span className="text-muted-foreground">Template hash:</span> <span className="text-foreground">{pageInfo.template_hash || "—"}</span></div>
                            <div><span className="text-muted-foreground">Content diff ratio:</span> <span className="text-foreground">{pageInfo.content_diff_ratio ?? "—"}</span></div>
                            <div><span className="text-muted-foreground">Title:</span> <span className="text-foreground">{pageInfo.title || "—"}</span></div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </>
              )}

              {selectedType === "edge" && selectedEdgeData && (
                <div className="space-y-3">
                  {/* Edge header */}
                  <div className="rounded-xl border border-border/40 bg-zinc-900/60 p-3 space-y-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs font-semibold" style={{ color: edgeColor(selectedEdgeData.edge_type) }}>
                        {selectedEdgeData.edge_type}
                      </span>
                      <Badge variant="outline" className="font-mono text-[10px]">
                        {(selectedEdgeData.confidence * 100).toFixed(0)}% confidence
                      </Badge>
                      {selectedEdgeData.needs_review && (
                        <Badge variant="outline" className="font-mono text-[10px] text-amber-400 border-amber-500/40">
                          needs review — fuzzy match, not merged
                        </Badge>
                      )}
                    </div>
                    <div className="font-mono text-[10px] text-muted-foreground space-y-0.5">
                      <div className="truncate">From: <span className="text-foreground">{selectedEdgeData.source.slice(0, 50)}</span></div>
                      <div className="truncate">To: <span className="text-foreground">{selectedEdgeData.target.slice(0, 50)}</span></div>
                      {selectedEdgeData.basis && (
                        <div className="pt-1">Matching rule: <span className="text-foreground">{selectedEdgeData.basis}</span></div>
                      )}
                      {selectedEdgeData.review_status && (
                        <div>Review: <span className="text-foreground">{selectedEdgeData.review_status}</span></div>
                      )}
                    </div>
                  </div>

                  {/* Evidence quote */}
                  {selectedEdgeData.evidence_quote ? (
                    <div>
                      <div className="mb-1.5 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">Verbatim Evidence</div>
                      <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-3">
                        <p className="font-mono text-[11px] text-emerald-300 leading-relaxed italic">
                          "{selectedEdgeData.evidence_quote}"
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-3 text-[11px] text-amber-400">
                      No verbatim evidence quote. Treat this relationship as inferred, not directly evidenced.
                    </div>
                  )}

                  {/* Source page info */}
                  {(() => {
                    const srcNode = nodes.find((n) => n.data.id === selectedEdgeData.source);
                    const srcPage = srcNode?.data.url ? data?.pages?.find((p) => p.url === srcNode.data.url) : null;
                    if (!srcPage) return null;
                    return (
                      <div className="rounded-xl border border-border/30 bg-zinc-900/40 p-3 space-y-1 font-mono text-[10px]">
                        <div className="text-[11px] font-semibold text-muted-foreground mb-2">Source Page</div>
                        <div><span className="text-muted-foreground">Onion:</span> <span className="text-foreground truncate block">{srcNode?.data.url}</span></div>
                        <div><span className="text-muted-foreground">Captured:</span> <span className="text-foreground">{srcPage.captured_at || "—"}</span></div>
                        <div><span className="text-muted-foreground">Server:</span> <span className="text-foreground">{srcPage.server_banner || "—"}</span></div>
                        <Button size="sm" variant="outline" className="mt-2 h-6 text-[10px]"
                          onClick={() => { handleSelect(srcNode!.data.id, "node", srcNode!.data); setDrawerTab("html"); loadHtml(srcNode!.data.url!); }}>
                          View Raw HTML
                        </Button>
                      </div>
                    );
                  })()}
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── Bottom panels ── */}
        {!isExpanded ? (
          <div className="border-t border-border/40 bg-zinc-950/80 grid grid-cols-1 gap-0 lg:grid-cols-3 divide-x divide-border/30 transition-all duration-300" style={{ maxHeight: 300 }}>

          {/* Community table */}
          <div className="overflow-y-auto p-3 lg:col-span-1">
            <div className="mb-2 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">Cluster Intelligence</div>
            <table className="w-full text-[10px]">
              <thead className="text-muted-foreground">
                <tr>
                  <th className="pb-1 text-left">Cluster</th>
                  <th className="pb-1 text-right">Actors</th>
                  <th className="pb-1 text-right">Onions</th>
                  <th className="pb-1 text-right">Wallets</th>
                  <th className="pb-1 text-right">Strong ≥80%</th>
                  <th className="pb-1 text-left pl-2">Dom. rel</th>
                </tr>
              </thead>
              <tbody>
                {communityTable.map((c) => (
                  <tr key={c.community}
                    onClick={() => setCommunityFilter(communityFilter === c.community ? null : c.community)}
                    className={`cursor-pointer border-b border-border/10 last:border-0 hover:bg-white/[0.02] transition-colors ${communityFilter === c.community ? "bg-primary/5" : ""}`}>
                    <td className="py-1 font-mono text-amber-400">#{c.community}</td>
                    <td className="py-1 text-right tabular-nums">{c.actors}</td>
                    <td className="py-1 text-right tabular-nums">{c.onions}</td>
                    <td className="py-1 text-right tabular-nums text-yellow-400">{c.wallets}</td>
                    <td className="py-1 text-right tabular-nums text-emerald-400">{c.highConfEdges}</td>
                    <td className="py-1 pl-2 font-mono text-muted-foreground truncate max-w-[80px]">{c.dominantRel}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Top pivots */}
          <div className="overflow-y-auto p-3 lg:col-span-1">
            <div className="mb-2 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">Top Pivot Entities</div>
            <div className="space-y-1.5">
              {topPivots.map((n) => (
                <div key={n.id}
                  onClick={() => { handleSelect(n.id, "node", n as any); setSelectedId(n.id); }}
                  className="flex items-center justify-between rounded border border-border/20 bg-zinc-900/40 px-2.5 py-1.5 cursor-pointer hover:bg-zinc-900 transition-colors">
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: nodeColor(n.node_type) }} />
                    <span className="font-mono text-[10px] text-foreground truncate">{n.label}</span>
                  </div>
                  <span className="font-mono text-[10px] text-muted-foreground shrink-0 ml-2">⊕{n.score.toFixed(1)}</span>
                </div>
              ))}
              {topPivots.length === 0 && <p className="text-[10px] text-muted-foreground">No pivot entities.</p>}
            </div>
          </div>

          {/* Bridge nodes + Cross-onion IOCs */}
          <div className="overflow-y-auto p-3 lg:col-span-1 space-y-4">
            <div>
              <div className="mb-2 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">Bridge Nodes</div>
              <div className="space-y-1">
                {bridgeNodes.map((n) => (
                  <div key={n.data.id}
                    onClick={() => handleSelect(n.data.id, "node", n.data)}
                    className="flex items-center justify-between cursor-pointer rounded border border-border/20 bg-zinc-900/40 px-2.5 py-1.5 hover:bg-zinc-900 transition-colors">
                    <span className="font-mono text-[10px] text-foreground truncate">{n.data.label}</span>
                    <Badge variant="outline" className="text-[9px] font-mono shrink-0 ml-2">deg {degreeMap[n.data.id] || n.data.degree}</Badge>
                  </div>
                ))}
                {bridgeNodes.length === 0 && <p className="text-[10px] text-muted-foreground">No bridge nodes detected.</p>}
              </div>
            </div>

            <div>
              <div className="mb-2 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">Cross-Onion Shared IOCs</div>
              <div className="space-y-1">
                {crossOnionIOCs.map((n) => (
                  <div key={n.id}
                    onClick={() => handleSelect(n.id, "node", n as any)}
                    className="flex items-center justify-between cursor-pointer rounded border border-border/20 bg-zinc-900/40 px-2.5 py-1.5 hover:bg-zinc-900 transition-colors">
                    <span className="font-mono text-[10px] text-foreground truncate">{n.label}</span>
                    <span className="text-[10px] text-primary shrink-0 ml-2">{n.onion_count} onions</span>
                  </div>
                ))}
                {crossOnionIOCs.length === 0 && <p className="text-[10px] text-muted-foreground">No shared IOCs across onions.</p>}
              </div>
            </div>
          </div>
        </div>
        ) : (
          <div className="border-t border-border/40 bg-zinc-950/90 px-4 py-2 flex items-center justify-between text-xs text-muted-foreground">
            <span className="font-mono text-[11px]">Bottom intelligence panels minimized · Canvas height maximized</span>
            <button
              onClick={() => setIsExpanded(false)}
              className="font-mono text-[11px] text-primary hover:underline flex items-center gap-1.5 cursor-pointer"
            >
              <MinimizeIcon className="h-3 w-3" />
              Restore panels (Normal view)
            </button>
          </div>
        )}
      </div>
    </AppShell>
  );
}
