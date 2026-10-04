"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { SearchIcon, ArrowRightIcon } from "@/components/icons";
import { Button } from "@/components/ui/button";

interface OnionPage {
  id: string;
  investigation_id: string;
  url: string;
  title: string;
  server_banner: string;
  favicon_mmh3: string;
  etag: string;
  template_hash: string;
  content_diff_ratio: number;
  created_at: string;
}

export default function OnionsPage() {
  const [pages, setPages] = useState<OnionPage[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const searchParam = params.get("search") || "";
    setFilter(searchParam);

    fetch("/api/onions")
      .then((r) => r.json())
      .then((d) => setPages(d.pages || []))
      .finally(() => setLoading(false));
  }, []);

  const filtered = pages.filter(
    (p) =>
      p.url.toLowerCase().includes(filter.toLowerCase()) ||
      (p.title || "").toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <AppShell>
      <div className="space-y-6 p-4 lg:p-6">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Onion Explorer</h1>
          <p className="text-sm text-muted-foreground">
            All captured hidden services — {pages.length} domains in vault.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <SearchIcon className="h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Filter by .onion URL or page title…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="max-w-sm font-mono text-sm"
          />
          <span className="text-xs text-muted-foreground">{filtered.length} results</span>
        </div>

        <Card className="border-border/50 bg-card/80">
          <CardContent className="p-0">
            <table className="w-full text-xs">
              <thead className="border-b border-border/50">
                <tr className="text-left text-muted-foreground">
                  <th className="px-4 py-3 font-medium">URL</th>
                  <th className="px-4 py-3 font-medium">Title</th>
                  <th className="px-4 py-3 font-medium">Server</th>
                  <th className="px-4 py-3 font-medium">mmh3</th>
                  <th className="px-4 py-3 font-medium">Δ Ratio</th>
                  <th className="px-4 py-3 font-medium">Captured</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-muted-foreground">Loading…</td>
                  </tr>
                )}
                {!loading && filtered.length === 0 && (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-muted-foreground">
                      No hidden services captured yet. Run an investigation to populate this vault.
                    </td>
                  </tr>
                )}
                {filtered.map((p) => (
                  <tr key={p.id} className="border-b border-border/20 last:border-0 hover:bg-muted/10">
                    <td className="max-w-[200px] truncate px-4 py-2.5 font-mono text-[10px] text-blue-400">{p.url}</td>
                    <td className="max-w-[160px] truncate px-4 py-2.5">{p.title || <span className="text-muted-foreground">—</span>}</td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-muted-foreground">{p.server_banner || "—"}</td>
                    <td className="px-4 py-2.5 font-mono text-[10px]">
                      {p.favicon_mmh3 ? (
                        <Badge variant="outline" className="text-[9px]">{p.favicon_mmh3}</Badge>
                      ) : "—"}
                    </td>
                    <td className="px-4 py-2.5 text-right tabular-nums">
                      {p.content_diff_ratio != null ? (p.content_diff_ratio * 100).toFixed(0) + "%" : "—"}
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">{new Date(p.created_at).toLocaleDateString()}</td>
                    <td className="px-4 py-2.5">
                      <a href={`/onions/${p.id}`}>
                        <Button size="sm" variant="ghost" className="h-6 px-2">
                          <ArrowRightIcon className="h-3 w-3" />
                        </Button>
                      </a>
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
