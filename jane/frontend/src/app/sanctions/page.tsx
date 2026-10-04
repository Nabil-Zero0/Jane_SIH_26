"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  SearchIcon,
  ShieldAlertIcon,
  NetworkIcon,
  GlobeIcon,
  ArrowRightIcon,
  ShieldCheckIcon,
} from "@/components/icons";

interface SanctionedEntity {
  id: string;
  type: string;
  value: string;
  evidence_quote: string;
  confidence: number;
  actor_id: string | null;
  actor_handle: string;
  category: string;
  risk_score: number;
  sanction_program: string;
  status: string;
}

interface SubgraphNode {
  id: string;
  label: string;
  node_type: string;
  community: number;
  degree: number;
}

interface SubgraphEdge {
  id: string;
  source: string;
  target: string;
  edge_type: string;
  confidence: number;
}

interface RegistryLink {
  name: string;
  url: string;
  authority: string;
}

export default function SanctionsPage() {
  const [entities, setEntities] = useState<SanctionedEntity[]>([]);
  const [subgraph, setSubgraph] = useState<{ nodes: SubgraphNode[]; edges: SubgraphEdge[] }>({
    nodes: [],
    edges: [],
  });
  const [registries, setRegistries] = useState<RegistryLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [selectedEntity, setSelectedEntity] = useState<SanctionedEntity | null>(null);

  useEffect(() => {
    fetch("/api/sanctions")
      .then((r) => r.json())
      .then((d) => {
        setEntities(d.sanctioned_entities || []);
        setSubgraph(d.subgraph || { nodes: [], edges: [] });
        setRegistries(d.registries || []);
        if (d.sanctioned_entities && d.sanctioned_entities.length > 0) {
          setSelectedEntity(d.sanctioned_entities[0]);
        }
      })
      .catch((e) => console.error(e))
      .finally(() => setLoading(false));
  }, []);

  const filtered = entities.filter(
    (s) =>
      s.value.toLowerCase().includes(filter.toLowerCase()) ||
      s.type.toLowerCase().includes(filter.toLowerCase()) ||
      s.actor_handle.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <AppShell>
      <div className="space-y-6 p-4 lg:p-6">
        {/* Page Header */}
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-xl font-bold tracking-tight">Sanctions & OFAC Watchboard</h1>
            <p className="text-sm text-muted-foreground">
              Designated cryptocurrency assets, blacklisted addresses, and multi-hop attribution graphs.
            </p>
          </div>
          <Badge variant="destructive" className="self-start text-xs font-mono">
            {loading ? "SCANNING..." : `${entities.length} DESIGNATED ASSETS`}
          </Badge>
        </div>

        {/* Official Registry Deep-Links Banner */}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {registries.map((reg) => (
            <a
              key={reg.name}
              href={reg.url}
              target="_blank"
              rel="noopener noreferrer"
              className="group rounded-xl border border-border/50 bg-card/60 p-3 backdrop-blur transition-all duration-200 hover:border-primary/50 hover:bg-card"
            >
              <div className="flex items-center justify-between text-xs font-semibold text-foreground group-hover:text-primary">
                <span>{reg.name}</span>
                <ArrowRightIcon className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">{reg.authority}</p>
            </a>
          ))}
        </div>

        {/* 1-Hop / 2-Hop Network Subgraph & Selected Entity Inspector */}
        <div className="grid gap-4 lg:grid-cols-3">
          {/* Subgraph Card */}
          <Card className="border-border/50 bg-card/80 backdrop-blur lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center justify-between text-sm">
                <span className="flex items-center gap-2">
                  <NetworkIcon className="h-4 w-4" /> 1-Hop / 2-Hop Sanctioned Network Subgraph
                </span>
                <Badge variant="secondary" className="text-[10px]">
                  {subgraph.nodes.length} Nodes · {subgraph.edges.length} Edges
                </Badge>
              </CardTitle>
              <CardDescription className="text-xs">
                Direct connections between sanctioned wallets, onion endpoints, and attributed operators
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="relative min-h-[280px] rounded-lg border border-border/40 bg-muted/10 p-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 max-h-[300px] overflow-y-auto pr-1">
                  {subgraph.edges.slice(0, 10).map((edge, idx) => (
                    <div
                      key={edge.id || idx}
                      className="rounded-md border border-border/30 bg-card/70 p-2.5 text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-semibold text-primary">{edge.edge_type}</span>
                        <span className="font-mono text-muted-foreground tabular-nums">
                          {(edge.confidence * 100).toFixed(0)}% Conf.
                        </span>
                      </div>
                      <div className="truncate font-mono text-[10px] text-muted-foreground">
                        <span className="text-foreground">Src:</span> {edge.source.replace("http://", "").slice(0, 24)}...
                      </div>
                      <div className="truncate font-mono text-[10px] text-muted-foreground">
                        <span className="text-foreground">Tgt:</span> {edge.target.replace("http://", "").slice(0, 24)}...
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Selected Entity Inspector */}
          <Card className="border-border/50 bg-card/80 backdrop-blur">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <ShieldAlertIcon className="h-4 w-4 text-red-400" /> Sanction Risk Dossier
              </CardTitle>
              <CardDescription className="text-xs">
                Target entity risk profile & program tags
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {selectedEntity ? (
                <>
                  <div className="space-y-1">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Address / Value</span>
                    <p className="break-all font-mono text-xs text-red-400 font-semibold bg-red-500/10 p-2 rounded border border-red-500/20">
                      {selectedEntity.value}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-muted-foreground">Type:</span>
                      <p className="font-medium text-foreground">{selectedEntity.type}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Attributed Actor:</span>
                      <p className="font-medium text-foreground">{selectedEntity.actor_handle}</p>
                    </div>
                  </div>

                  <div className="rounded-lg border border-border/40 bg-muted/20 p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold">Composite Risk Score</span>
                      <Badge variant="destructive" className="font-mono text-xs">
                        {selectedEntity.risk_score} / 100
                      </Badge>
                    </div>
                    <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full rounded-full bg-red-500 transition-all duration-500"
                        style={{ width: `${selectedEntity.risk_score}%` }}
                      />
                    </div>
                    <div className="text-[10px] text-muted-foreground">
                      Program: <span className="text-foreground">{selectedEntity.sanction_program}</span>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Proof Quote</span>
                    <p className="text-xs text-muted-foreground italic bg-muted/30 p-2 rounded">
                      "{selectedEntity.evidence_quote}"
                    </p>
                  </div>
                </>
              ) : (
                <div className="py-10 text-center text-xs text-muted-foreground">
                  Select an asset from the table below to inspect details.
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Filter Input */}
        <div className="flex items-center gap-2">
          <SearchIcon className="h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Filter by cryptocurrency address, type, or operator handle..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="max-w-sm font-mono text-xs"
          />
        </div>

        {/* Table */}
        <Card className="border-border/50 bg-card/80 backdrop-blur">
          <CardContent className="p-0">
            <table className="w-full text-xs">
              <thead className="border-b border-border/50 text-muted-foreground">
                <tr>
                  <th className="px-4 py-3 text-left">Asset Type</th>
                  <th className="px-4 py-3 text-left">Address / Identifier</th>
                  <th className="px-4 py-3 text-left">Attributed Actor</th>
                  <th className="px-4 py-3 text-left">Risk Meter</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {!loading && filtered.length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-10 text-center text-muted-foreground">
                      No sanctioned entities match your filter query.
                    </td>
                  </tr>
                )}
                {filtered.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => setSelectedEntity(item)}
                    className={`cursor-pointer border-b border-border/20 last:border-0 hover:bg-muted/40 transition-colors ${selectedEntity?.id === item.id ? "bg-muted/30" : ""}`}
                  >
                    <td className="px-4 py-3">
                      <Badge variant="destructive" className="text-[10px]">
                        {item.type}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 font-mono text-red-400 font-semibold max-w-xs truncate">
                      {item.value}
                    </td>
                    <td className="px-4 py-3 font-medium text-foreground">
                      {item.actor_handle}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs tabular-nums text-foreground">{item.risk_score}</span>
                        <div className="h-1.5 w-16 rounded-full bg-muted overflow-hidden">
                          <div
                            className="h-full bg-red-500"
                            style={{ width: `${item.risk_score}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEntity(item);
                        }}
                        className="h-7 text-xs"
                      >
                        Inspect
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
