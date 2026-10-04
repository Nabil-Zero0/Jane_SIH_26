"use client";

import { useEffect, useState } from "react";
import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";

type CanonicalNode = Node<{ label?: string; node_type?: string; [key: string]: unknown }>;
type CanonicalEdge = Edge<{ edge_type?: string; confidence?: number; [key: string]: unknown }>;

type GraphElements = {
  nodes?: Array<{ data?: Record<string, unknown> }>;
  edges?: Array<{ data?: Record<string, unknown> }>;
};

type GlobalGraphResponse = {
  investigation_count?: number;
  graph_elements?: GraphElements;
};

const NODE_COLORS: Record<string, string> = {
  Actor: "#fb7185",
  Marketplace: "#38bdf8",
  Product: "#fbbf24",
  SharedIdentifier: "#a78bfa",
  ClearnetAccount: "#2dd4bf",
};

function nodeColor(type: string) {
  return NODE_COLORS[type] ?? "#94a3b8";
}

function buildNodes(items: GraphElements["nodes"]): CanonicalNode[] {
  return (items ?? []).map((item, index) => {
    const data = item.data ?? {};
    const type = String(data.node_type ?? "Unknown");
    const columns = 4;
    return {
      id: String(data.id ?? `node-${index}`),
      type: "default",
      position: { x: (index % columns) * 260, y: Math.floor(index / columns) * 125 },
      data: { ...data, label: String(data.label ?? data.id ?? "Unknown") },
      style: {
        width: 205,
        border: `1px solid ${nodeColor(type)}`,
        borderRadius: 10,
        background: "rgba(9, 12, 20, 0.96)",
        color: "#f8fafc",
        boxShadow: `0 0 22px ${nodeColor(type)}22`,
        fontSize: 11,
        fontFamily: "var(--font-mono)",
      },
    };
  });
}

function buildEdges(items: GraphElements["edges"]): CanonicalEdge[] {
  return (items ?? []).map((item, index) => {
    const data = item.data ?? {};
    return {
      id: String(data.id ?? `edge-${index}`),
      source: String(data.source ?? ""),
      target: String(data.target ?? ""),
      label: String(data.edge_type ?? data.label ?? "RELATED"),
      type: "smoothstep",
      animated: false,
      markerEnd: { type: MarkerType.ArrowClosed, color: "#64748b" },
      style: { stroke: "#64748b", strokeWidth: 1.25 },
      labelStyle: { fill: "#94a3b8", fontSize: 9, fontFamily: "var(--font-mono)" },
      labelBgStyle: { fill: "#090c14", fillOpacity: 0.9 },
      data,
    };
  });
}

export function GlobalThreatGraph() {
  const [nodes, setNodes] = useState<CanonicalNode[]>([]);
  const [edges, setEdges] = useState<CanonicalEdge[]>([]);
  const [investigationCount, setInvestigationCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/graph/global")
      .then((response) => {
        if (!response.ok) throw new Error(`Global graph request failed (${response.status})`);
        return response.json() as Promise<GlobalGraphResponse>;
      })
      .then((payload) => {
        setNodes(buildNodes(payload.graph_elements?.nodes));
        setEdges(buildEdges(payload.graph_elements?.edges));
        setInvestigationCount(payload.investigation_count ?? 0);
      })
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Global graph unavailable"))
      .finally(() => setLoading(false));
  }, []);

  return (
    <section className="overflow-hidden rounded-xl border border-dashed border-border/60 bg-zinc-950/90">
      <div className="flex flex-col gap-2 border-b border-border/40 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold">Global Threat Graph</h2>
            <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[10px] text-cyan-300">CANONICAL</span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">Canonical entities and relationships accumulated across {investigationCount} investigation{investigationCount === 1 ? "" : "s"}.</p>
        </div>
        <div className="font-mono text-[10px] text-muted-foreground">{nodes.length} nodes · {edges.length} relationships</div>
      </div>
      <div className="h-[560px] w-full">
        {loading ? (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">Loading global graph…</div>
        ) : error ? (
          <div className="flex h-full items-center justify-center px-6 text-center text-xs text-red-300">{error}</div>
        ) : nodes.length === 0 ? (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">No canonical graph entities yet.</div>
        ) : (
          <ReactFlow nodes={nodes} edges={edges} fitView fitViewOptions={{ padding: 0.2 }} minZoom={0.15} maxZoom={1.5} attributionPosition="bottom-left">
            <Background color="#334155" gap={24} size={1} />
            <Controls showInteractive={false} />
            <MiniMap nodeColor={(node) => nodeColor(String(node.data?.node_type ?? ""))} maskColor="rgba(3, 7, 18, 0.72)" />
          </ReactFlow>
        )}
      </div>
    </section>
  );
}
