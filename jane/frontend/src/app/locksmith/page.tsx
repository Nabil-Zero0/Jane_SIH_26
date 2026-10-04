"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  KeyIcon,
  ServerCrashIcon,
  GlobeIcon,
  CopyIcon,
  CheckIcon,
  ArrowRightIcon,
  ShieldAlertIcon,
} from "@/components/icons";

interface FaviconItem {
  id: string;
  url: string;
  favicon_mmh3: string;
  server_banner: string;
  etag: string;
  title: string;
}

interface ShodanDork {
  hash: string;
  dork: string;
  page_url: string;
}

interface LeakedIP {
  value: string;
  evidence_quote: string;
  page_url: string;
}

interface LocksmithData {
  favicon_hashes: FaviconItem[];
  shodan_dorks: ShodanDork[];
  leaked_ips: LeakedIP[];
}

export default function LocksmithPage() {
  const [data, setData] = useState<LocksmithData | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/locksmith")
      .then((r) => r.json())
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(text);
    setTimeout(() => setCopied(null), 2000);
  };

  // Group favicons & banners for distribution
  const bannerCounts: Record<string, number> = {};
  (data?.favicon_hashes || []).forEach((f) => {
    const b = f.server_banner || "Undisclosed";
    bannerCounts[b] = (bannerCounts[b] || 0) + 1;
  });

  return (
    <AppShell>
      <div className="space-y-6 p-4 lg:p-6">
        {/* Page Header */}
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-xl font-bold tracking-tight">Locksmith Infrastructure Intelligence</h1>
            <p className="text-sm text-muted-foreground">
              Side-channel infrastructure de-anonymization: 16&times;16 favicon hashes, server banners, and clearnet leaks.
            </p>
          </div>
          <Badge variant="destructive" className="self-start text-xs font-mono">
            {data?.leaked_ips?.length ?? 0} CLEARNET IPS EXPOSED
          </Badge>
        </div>

        {/* Server Banner Distribution & ETag Correlation Row */}
        <div className="grid gap-4 lg:grid-cols-3">
          {/* Server Banner Treemap / Breakdown */}
          <Card className="border-border/50 bg-card/80 backdrop-blur lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <ServerCrashIcon className="h-4 w-4 text-primary" /> Server Banner Footprint & Treemap
              </CardTitle>
              <CardDescription className="text-xs">
                Exposed HTTP server headers across scraped hidden services
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {Object.entries(bannerCounts).map(([banner, count]) => (
                  <div
                    key={banner}
                    className="rounded-xl border border-border/40 bg-muted/20 p-3 space-y-1"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-foreground truncate">{banner}</span>
                      <Badge variant="secondary" className="text-[10px] font-mono">
                        {count} hosts
                      </Badge>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full bg-primary"
                        style={{ width: `${Math.min(100, count * 35)}%` }}
                      />
                    </div>
                    <div className="text-[10px] text-muted-foreground font-mono truncate">
                      Default Debian/Tor configuration
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* ETag Cryptographic Analyzer */}
          <Card className="border-border/50 bg-card/80 backdrop-blur">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <KeyIcon className="h-4 w-4" /> ETag Cryptographic Sync
              </CardTitle>
              <CardDescription className="text-xs">
                Synchronized caching signatures revealing identical origin webroots
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {(data?.favicon_hashes || [])
                .filter((f) => f.etag)
                .slice(0, 4)
                .map((item, idx) => (
                  <div
                    key={item.id || idx}
                    className="rounded-lg border border-border/30 bg-muted/10 p-2.5 space-y-1 text-xs"
                  >
                    <div className="flex items-center justify-between font-mono text-[11px]">
                      <span className="text-foreground font-semibold truncate max-w-[170px]">{item.etag}</span>
                      <Badge variant="outline" className="text-[9px]">SYNCED</Badge>
                    </div>
                    <div className="text-[10px] text-muted-foreground font-mono truncate">
                      Host: {item.url.replace("http://", "").slice(0, 24)}...
                    </div>
                  </div>
                ))}
            </CardContent>
          </Card>
        </div>

        {/* Shodan Favicon Dorks with 16x16 Preview */}
        <Card className="border-border/50 bg-card/80 backdrop-blur">
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2">
                <GlobeIcon className="h-4 w-4" /> Shodan Favicon MMH3 Signatures ({data?.shodan_dorks?.length ?? 0} Hashes)
              </span>
              <span className="text-xs text-muted-foreground">Clearnet cross-correlation queries</span>
            </CardTitle>
            <CardDescription className="text-xs">
              Direct dork syntax to locate origin servers exposing identical favicon checksums in Shodan
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {!loading && (data?.shodan_dorks?.length ?? 0) === 0 && (
              <p className="py-8 text-center text-xs text-muted-foreground">
                No favicon hashes discovered in collected drop archives.
              </p>
            )}
            {(data?.shodan_dorks ?? []).map((d, i) => (
              <div
                key={i}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-border/40 bg-muted/20 p-3"
              >
                <div className="flex items-center gap-3">
                  {/* 16x16 Favicon Visual Simulation */}
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded border border-border/60 bg-muted font-mono text-[10px] font-bold text-primary shadow-inner">
                    16²
                  </div>
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono text-[10px]">
                        MMH3: {d.hash}
                      </Badge>
                      <code className="text-[11px] font-mono font-semibold text-foreground">
                        {d.dork}
                      </code>
                    </div>
                    <div className="text-[10px] text-muted-foreground font-mono truncate max-w-md">
                      Source: {d.page_url}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-start sm:self-center">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => copyToClipboard(d.dork)}
                    className="h-7 text-xs flex items-center gap-1"
                  >
                    {copied === d.dork ? <CheckIcon className="h-3 w-3 text-emerald-400" /> : <CopyIcon className="h-3 w-3" />}
                    {copied === d.dork ? "Copied" : "Copy Dork"}
                  </Button>
                  <a
                    href={`https://www.shodan.io/search?query=${encodeURIComponent(d.dork)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 rounded-md border border-primary/40 bg-primary/10 px-2.5 py-1 text-xs font-semibold text-primary hover:bg-primary/20 transition-colors"
                  >
                    Search Shodan <ArrowRightIcon className="h-3 w-3" />
                  </a>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Leaked Clearnet Origin IPs */}
        <Card className="border-border/50 bg-card/80 backdrop-blur">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <ShieldAlertIcon className="h-4 w-4 text-red-400" /> Leaked Clearnet Origin IPs ({data?.leaked_ips?.length ?? 0})
            </CardTitle>
            <CardDescription className="text-xs">
              Deanonymized IP addresses discovered in hidden service server responses and HTML comments
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {!loading && (data?.leaked_ips?.length ?? 0) === 0 && (
              <p className="py-8 text-center text-xs text-muted-foreground">
                No leaked IP addresses detected in current data.
              </p>
            )}
            {(data?.leaked_ips ?? []).map((ip, i) => (
              <div
                key={i}
                className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm font-bold text-red-400">{ip.value}</span>
                  <Badge variant="destructive" className="text-[10px]">
                    EXPOSED ORIGIN
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground italic">
                  "{ip.evidence_quote}"
                </p>
                <div className="text-[10px] text-muted-foreground font-mono">
                  Leaked from: {ip.page_url}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
