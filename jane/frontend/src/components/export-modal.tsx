"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollIcon, DatabaseIcon, BarChart3Icon, XIcon } from "@/components/icons";

interface ExportModalProps {
  investigationId?: string;
  investigationIds?: string[];
  title?: string;
  onClose: () => void;
}

export function ExportModal({ investigationId, investigationIds, title, onClose }: ExportModalProps) {
  const [exporting, setExporting] = useState(false);

  const ids = investigationIds && investigationIds.length > 0 
    ? investigationIds 
    : investigationId 
    ? [investigationId] 
    : [];

  const isBulk = ids.length > 1;

  const handleExport = async (format: "pdf" | "json" | "csv") => {
    if (ids.length === 0) return;
    setExporting(true);
    try {
      const endpoint = isBulk
        ? `/api/investigations/export?ids=${encodeURIComponent(ids.join(","))}&format=${format}`
        : `/api/investigations/${encodeURIComponent(ids[0])}/export?format=${format}`;

      const res = await fetch(endpoint);
      if (!res.ok) throw new Error(`Export failed: ${res.statusText}`);
      
      // Determine filename from header or fallback
      let filename = `jane_${isBulk ? `${ids.length}_cases` : ids[0]}.${format === "csv" ? "zip" : format}`;
      const disp = res.headers.get("Content-Disposition");
      if (disp) {
        const match = disp.match(/filename="?([^"]+)"?/);
        if (match && match[1]) filename = match[1];
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      onClose();
    } catch (err) {
      console.error("Export failed:", err);
      alert("Export failed. Check console for details.");
    } finally {
      setExporting(false);
    }
  };

  const modalTitle = title || (isBulk ? `Export ${ids.length} Selected Cases` : "Export Investigation");
  const caseDesc = isBulk
    ? `Package ${ids.length} selected investigations into unified dossier`
    : `Choose export format for case ${ids[0]?.slice(0, 12)}...`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <Card className="w-full max-w-lg border-border/50 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <CardContent className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-bold">{modalTitle}</h2>
              <p className="text-xs text-muted-foreground mt-0.5">{caseDesc}</p>
            </div>
            <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
              <XIcon className="h-5 w-5" />
            </button>
          </div>

          <div className="space-y-3">
            <button
              onClick={() => handleExport("pdf")}
              disabled={exporting}
              className="w-full flex items-start gap-3.5 p-4 rounded-lg border border-border/50 bg-muted/10 hover:bg-muted/20 transition text-left disabled:opacity-50 group"
            >
              <div className="p-2 rounded-md bg-primary/10 text-primary group-hover:bg-primary/20 transition mt-0.5">
                <ScrollIcon className="h-5 w-5" />
              </div>
              <div className="flex-1">
                <div className="font-semibold text-sm flex items-center justify-between">
                  <span>PDF Forensic Report</span>
                  <span className="text-[10px] font-mono uppercase bg-primary/15 text-primary px-1.5 py-0.5 rounded">Dossier</span>
                </div>
                <div className="text-xs text-muted-foreground mt-1 leading-relaxed">
                  Human-readable forensic report with executive assessment, persona cards, infrastructure analysis, graph summary, and E-001 evidence appendix.
                </div>
              </div>
            </button>

            <button
              onClick={() => handleExport("json")}
              disabled={exporting}
              className="w-full flex items-start gap-3.5 p-4 rounded-lg border border-border/50 bg-muted/10 hover:bg-muted/20 transition text-left disabled:opacity-50 group"
            >
              <div className="p-2 rounded-md bg-blue-500/10 text-blue-400 group-hover:bg-blue-500/20 transition mt-0.5">
                <DatabaseIcon className="h-5 w-5" />
              </div>
              <div className="flex-1">
                <div className="font-semibold text-sm flex items-center justify-between">
                  <span>JSON Intelligence Package</span>
                  <span className="text-[10px] font-mono uppercase bg-blue-500/15 text-blue-400 px-1.5 py-0.5 rounded">Forensic</span>
                </div>
                <div className="text-xs text-muted-foreground mt-1 leading-relaxed">
                  Complete structured intelligence package with SHA-256 integrity hash, raw evidence provenance, full graph nodes/edges, and pipeline run events.
                </div>
              </div>
            </button>

            <button
              onClick={() => handleExport("csv")}
              disabled={exporting}
              className="w-full flex items-start gap-3.5 p-4 rounded-lg border border-border/50 bg-muted/10 hover:bg-muted/20 transition text-left disabled:opacity-50 group"
            >
              <div className="p-2 rounded-md bg-emerald-500/10 text-emerald-400 group-hover:bg-emerald-500/20 transition mt-0.5">
                <BarChart3Icon className="h-5 w-5" />
              </div>
              <div className="flex-1">
                <div className="font-semibold text-sm flex items-center justify-between">
                  <span>CSV Archive (ZIP)</span>
                  <span className="text-[10px] font-mono uppercase bg-emerald-500/15 text-emerald-400 px-1.5 py-0.5 rounded">7 Tables</span>
                </div>
                <div className="text-xs text-muted-foreground mt-1 leading-relaxed">
                  Spreadsheet-ready tables: summary, pages, threat actors, identifiers, graph nodes, graph edges, and pipeline events.
                </div>
              </div>
            </button>
          </div>

          {exporting && (
            <div className="mt-4 flex items-center justify-center gap-2 text-sm text-muted-foreground">
              <span className="inline-block h-2 w-2 animate-ping rounded-full bg-primary" />
              Generating export package...
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
