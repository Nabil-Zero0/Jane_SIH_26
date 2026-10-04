"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CopyIcon } from "@/components/icons";

export default function OnionDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const [data, setData] = useState<any>(null);
  const [rawHtml, setRawHtml] = useState<string>("");
  const [tab, setTab] = useState<"preview" | "raw">("preview");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/onions?id=${id}`)
      .then((r) => r.json())
      .then((d) => {
        setData(d);
        if (d.page?.url) {
          fetch(`/api/snapshot?url=${encodeURIComponent(d.page.url)}`)
            .then((r) => r.text())
            .then(setRawHtml);
        }
        setLoading(false);
      });
  }, [id]);

  if (loading) return <AppShell><div className="p-8 text-muted-foreground">Loading forensic vault entry…</div></AppShell>;
  if (!data?.page) return <AppShell><div className="p-8 text-red-400">Page not found.</div></AppShell>;

  const page = data.page;
  const idents: any[] = data.identifiers || [];

  return (
    <AppShell>
      <div className="space-y-6 p-4 lg:p-6">
        <div>
          <p className="font-mono text-xs text-muted-foreground">{page.id}</p>
          <h1 className="text-xl font-bold">{page.title || "Untitled Hidden Service"}</h1>
          <p className="font-mono text-sm text-blue-400">{page.url}</p>
        </div>

        {/* HTTP Fingerprint */}
        <Card className="border-border/50 bg-card/80">
          <CardHeader><CardTitle className="text-sm">HTTP Fingerprint</CardTitle></CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
              {[
                { label: "Server Banner", value: page.server_banner },
                { label: "Favicon mmh3", value: page.favicon_mmh3 },
                { label: "ETag", value: page.etag },
                { label: "Template Hash", value: page.template_hash },
                { label: "Content Δ Ratio", value: page.content_diff_ratio != null ? `${(page.content_diff_ratio * 100).toFixed(1)}%` : null },
                { label: "Captured", value: new Date(page.created_at).toLocaleString() },
              ].map(({ label, value }) => (
                <div key={label} className="rounded border border-border/40 bg-muted/20 px-3 py-2">
                  <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
                  <div className="mt-0.5 truncate font-mono text-xs">{value || "—"}</div>
                </div>
              ))}
            </div>
            {page.favicon_mmh3 && (
              <div className="mt-3 flex items-center gap-2">
                <code className="rounded bg-muted/30 px-2 py-1 font-mono text-xs">
                  http.favicon.hash:{page.favicon_mmh3}
                </code>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-6 px-2 text-xs"
                  onClick={() => navigator.clipboard.writeText(`http.favicon.hash:${page.favicon_mmh3}`)}
                >
                  <CopyIcon className="h-3 w-3" /> Copy Shodan
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Dual-pane inspector */}
        <Card className="border-border/50 bg-card/80">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-sm">Page Inspector</CardTitle>
            <div className="flex gap-1">
              {(["preview", "raw"] as const).map((t) => (
                <Button
                  key={t}
                  size="sm"
                  variant={tab === t ? "default" : "ghost"}
                  className="h-6 px-2 text-xs capitalize"
                  onClick={() => setTab(t)}
                >
                  {t}
                </Button>
              ))}
            </div>
          </CardHeader>
          <CardContent>
            {tab === "preview" ? (
              rawHtml ? (
                <iframe
                  srcDoc={rawHtml}
                  sandbox="allow-same-origin"
                  className="h-96 w-full rounded border border-border/30 bg-white"
                  title="Defanged DOM Preview"
                />
              ) : (
                <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
                  Loading preview…
                </div>
              )
            ) : (
              <pre className="max-h-96 overflow-auto rounded bg-muted/20 p-3 font-mono text-[11px] leading-5">
                {rawHtml || "Raw HTML not available."}
              </pre>
            )}
          </CardContent>
        </Card>

        {/* Extracted IOCs */}
        {idents.length > 0 && (
          <Card className="border-border/50 bg-card/80">
            <CardHeader><CardTitle className="text-sm">Extracted Indicators ({idents.length})</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-2">
                {idents.map((ioc: any) => (
                  <div key={ioc.id} className="flex items-start gap-2 rounded border border-border/30 bg-muted/10 px-3 py-2">
                    <Badge variant="outline" className="shrink-0 text-[10px]">{ioc.type}</Badge>
                    <span className="break-all font-mono text-[11px]">{ioc.value}</span>
                    {ioc.is_sanctioned === 1 && (
                      <Badge variant="destructive" className="ml-auto shrink-0 text-[10px]">SANCTIONED</Badge>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}
