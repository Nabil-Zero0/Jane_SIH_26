"use client";

import React, { useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ShieldAlertIcon,
  ShieldCheckIcon,
  AlertCircleIcon,
  ClockIcon,
  CheckIcon,
  ScrollIcon,
  ArrowRightIcon,
  ArrowUpIcon,
  CopyIcon,
  CheckCircle2Icon,
  KeyIcon,
  GlobeIcon,
  DatabaseIcon,
  ActivityIcon,
} from "@/components/icons";

interface SectionLink {
  id: string;
  num: string;
  title: string;
  badge?: string;
}

const SECTIONS: SectionLink[] = [
  { id: "executive-summary", num: "01", title: "Executive Summary & Operational Scope", badge: "Mandate" },
  { id: "legal-position", num: "02", title: "Legal & Institutional Posture", badge: "Scope" },
  { id: "it-act-2000", num: "03", title: "IT Act, 2000 (Sections 43 & 66)", badge: "Statute" },
  { id: "cert-in-directions", num: "04", title: "CERT-In Directions (6-Hour Window)", badge: "Compliance" },
  { id: "dpdp-act-2023", num: "05", title: "DPDP Act, 2023 & Data Minimization", badge: "Privacy" },
  { id: "mha-i4c", num: "06", title: "MHA & I4C Institutional Context", badge: "Governance" },
  { id: "operating-modes", num: "07", title: "Operational Modes & State Matrix", badge: "Matrix" },
  { id: "permitted-activities", num: "08", title: "Permitted Activities (Passive OSINT)", badge: "Permitted" },
  { id: "prohibited-activities", num: "09", title: "Prohibited Intrusive Activities", badge: "Restricted" },
  { id: "sensitive-endpoints", num: "10", title: "Sensitive Path Probing Blacklist", badge: "Blacklist" },
  { id: "authorized-lab-mode", num: "11", title: "Controlled Lab Mode Protocol", badge: "Lab Only" },
  { id: "attribution-taxonomy", num: "12", title: "3-Tier Attribution Taxonomy", badge: "Forensics" },
  { id: "quarantine-protocol", num: "13", title: "Content Safety & Quarantine Circuit", badge: "Protocol" },
  { id: "evidence-integrity", num: "14", title: "Cryptographic Custody & Reports", badge: "Evidence" },
  { id: "incident-escalation", num: "15", title: "Incident Escalation Workflow", badge: "Escalation" },
  { id: "technical-safeguards", num: "16", title: "System Defaults & Guardrails", badge: "Runtime" },
  { id: "operator-pledge", num: "17", title: "Operator Ethical Acknowledgement", badge: "Affirmation" },
  { id: "statutory-citations", num: "18", title: "Statutory Citations & References", badge: "Authorities" },
];

function LegalStatute({
  children,
  href,
}: {
  children: React.ReactNode;
  href?: string;
}) {
  if (href) {
    return (
      <a
        href={href}
        target="_blank"
        rel="noreferrer"
        className="underline decoration-amber-400/40 decoration-1 underline-offset-[3px] font-medium text-zinc-200 hover:text-amber-200 hover:decoration-amber-300 transition-colors"
      >
        {children}
      </a>
    );
  }
  return (
    <span className="underline decoration-amber-400/35 decoration-1 underline-offset-[3px] font-medium text-zinc-200">
      {children}
    </span>
  );
}

export default function PolicyPage() {
  const [copiedConfig, setCopiedConfig] = useState(false);
  const [activeSection, setActiveSection] = useState("executive-summary");
  const [pledgeChecked, setPledgeChecked] = useState({
    scope: false,
    passive: false,
    noBypass: false,
    leadsOnly: false,
    quarantine: false,
  });

  const allPledged = Object.values(pledgeChecked).every(Boolean);

  const safeConfigCode = `# Jane Defensive Core Configuration Presets
# Enforced by pipeline/orchestrator.py & whonix/daemon.py

SAFE_MODE=true
PASSIVE_OSINT_MODE=true
ACTIVE_PROBING=false
AUTHORIZED_LAB_MODE=false

ALLOW_FORM_SUBMISSION=false
ALLOW_AUTHENTICATION=false
ALLOW_REGISTRATION=false
ALLOW_ACTOR_CONTACT=false
ALLOW_CRYPTO_TRANSACTIONS=false

DOWNLOAD_BINARIES=false
DOWNLOAD_ARCHIVES=false
DOWNLOAD_ATTACHMENTS=false
RENDER_IMAGES=false
RENDER_VIDEO=false

MAX_RESPONSE_BYTES=500000
MAX_DEPTH=1
MAX_PAGES_PER_ONION=5
REQUEST_TIMEOUT_SECONDS=30
PER_DOMAIN_RATE_LIMIT_SECONDS=3

REQUIRE_EVIDENCE_QUOTES=true
REQUIRE_AUTHORIZED_SCOPE_FOR_PROBES=true
ENABLE_SAFETY_QUARANTINE=true
ENABLE_EXPORT_AUDIT_LOG=true
RAW_HTML_RETENTION_DAYS=7`;

  const copyConfigToClipboard = () => {
    navigator.clipboard.writeText(safeConfigCode);
    setCopiedConfig(true);
    setTimeout(() => setCopiedConfig(false), 2200);
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <AppShell>
      <div className="space-y-12 pb-24 text-zinc-300">
        {/* Top Hero Container — Double Bezel Luxury Architecture */}
        <div className="rounded-[1.75rem] border border-white/[0.06] bg-zinc-950/60 p-1.5 shadow-[0_1px_1px_rgba(0,0,0,0.5)]">
          <div className="relative overflow-hidden rounded-[calc(1.75rem-0.375rem)] border border-white/[0.08] bg-gradient-to-b from-[#141416]/95 via-[#0e0e10]/95 to-[#0a0a0c]/98 p-6 md:p-10 shadow-[inset_0_1px_1px_rgba(255,255,255,0.06)]">
            {/* Subtle Brushed Gold Accent Hairline at the Top */}
            <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-amber-300/30 to-transparent" />

            <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
              <div className="space-y-3.5 max-w-3xl">
                {/* Eyebrow Tag */}
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-400/25 bg-amber-400/[0.04] px-3 py-1 font-mono text-[10px] uppercase tracking-[0.2em] font-medium text-amber-200/90">
                    <span className="h-1.5 w-1.5 rounded-full bg-amber-300/80 shadow-[0_0_8px_rgba(245,158,11,0.5)]" />
                    SIH 26151 • Policy v1.0
                  </span>
                  <span className="rounded-full border border-white/[0.08] bg-white/[0.02] px-3 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-400">
                    Passive Defensive OSINT
                  </span>
                  <span className="rounded-full border border-white/[0.08] bg-white/[0.02] px-3 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-500">
                    Audit Certified
                  </span>
                </div>

                <h1 className="text-2xl font-medium tracking-tight text-zinc-100 md:text-3xl lg:text-4xl font-sans">
                  Rules of Engagement & Legal Compliance Policy
                </h1>

                <p className="text-sm leading-relaxed text-zinc-400 font-normal">
                  Standard operating doctrine governing autonomous dark-web intelligence gathering, technical fingerprinting,
                  chain of custody preservation, and privacy-preserving attribution within the Jane research platform.
                </p>
              </div>

              {/* Action Buttons with Button-in-Button Architecture */}
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  variant="outline"
                  size="sm"
                  className="rounded-full border-white/[0.1] bg-white/[0.03] px-4 py-2 text-xs font-normal text-zinc-300 hover:border-white/[0.18] hover:bg-white/[0.06] transition-all duration-300 ease-[cubic-bezier(0.32,0.72,0,1)]"
                  onClick={() => window.print()}
                >
                  <ScrollIcon className="h-3.5 w-3.5 text-zinc-400 mr-2" />
                  Print / Export Dossier
                </Button>

                <a href="#operator-pledge">
                  <Button
                    size="sm"
                    className="group relative rounded-full border border-amber-400/30 bg-amber-400/[0.08] px-4 py-2 text-xs font-medium text-amber-200/90 shadow-[inset_0_1px_1px_rgba(245,158,11,0.2)] hover:bg-amber-400/[0.14] hover:border-amber-400/40 transition-all duration-300 ease-[cubic-bezier(0.32,0.72,0,1)] active:scale-[0.98]"
                  >
                    <span>Operator Pledge</span>
                    <span className="ml-2 flex h-5 w-5 items-center justify-center rounded-full bg-amber-300/15 group-hover:translate-x-0.5 transition-transform duration-300">
                      <ArrowRightIcon className="h-3 w-3 text-amber-200" />
                    </span>
                  </Button>
                </a>
              </div>
            </div>

            {/* Restrained Institutional Notice Banner */}
            <div className="mt-8 flex items-start gap-3.5 rounded-xl border border-amber-400/15 bg-amber-400/[0.02] p-4 text-xs text-zinc-300">
              <ShieldAlertIcon className="h-4 w-4 shrink-0 text-amber-300/80 mt-0.5" />
              <div className="space-y-1 leading-relaxed">
                <span className="font-medium text-amber-200/90">Institutional Operational Advisory (Not Legal Counsel):</span>
                <p className="text-zinc-400 text-[11px]">
                  This document specifies operational constraints for the Jane platform. Student research status, participation in the
                  Smart India Hackathon, or addressing government problem statements does <strong>not</strong> grant legal immunity,
                  investigative authority, or permission to probe or access third-party computer resources without written authorization under <LegalStatute>Indian law</LegalStatute>.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Core Layout Grid: Sticky Minimal Navigator on Left + Main Content Column on Right */}
        <div className="grid grid-cols-1 gap-10 lg:grid-cols-12">
          {/* Left Column: Quiet, High-Density Table of Contents */}
          <aside className="lg:col-span-4 xl:col-span-3">
            <div className="sticky top-6 space-y-4">
              <div className="rounded-[1.25rem] border border-white/[0.06] bg-zinc-950/60 p-1">
                <div className="rounded-[calc(1.25rem-0.25rem)] border border-white/[0.06] bg-[#0c0c0e]/90 p-3.5 backdrop-blur-md">
                  <div className="flex items-center justify-between pb-3 border-b border-white/[0.06] px-1">
                    <span className="font-mono text-[10px] uppercase tracking-[0.2em] font-medium text-zinc-400">
                      Policy Index
                    </span>
                    <span className="font-mono text-[9px] text-amber-300/80 px-1.5 py-0.5 rounded border border-amber-400/20 bg-amber-400/[0.05]">
                      18 Provisions
                    </span>
                  </div>

                  <nav className="mt-2.5 max-h-[calc(100vh-14rem)] overflow-y-auto space-y-0.5 pr-1 text-xs">
                    {SECTIONS.map((sec) => (
                      <a
                        key={sec.id}
                        href={`#${sec.id}`}
                        onClick={() => setActiveSection(sec.id)}
                        className={`group flex items-center justify-between rounded-lg px-2.5 py-1.5 transition-all duration-200 ${
                          activeSection === sec.id
                            ? "bg-white/[0.06] text-zinc-100 font-medium"
                            : "text-zinc-400 hover:bg-white/[0.03] hover:text-zinc-200"
                        }`}
                      >
                        <div className="flex items-center gap-2 truncate pr-2">
                          <span className="font-mono text-[10px] text-zinc-500 group-hover:text-amber-300/70 transition-colors">
                            {sec.num}
                          </span>
                          <span className="truncate text-[11px]">{sec.title.replace(/^\d+\.\s*/, "")}</span>
                        </div>
                        {sec.badge && (
                          <span className="shrink-0 font-mono text-[9px] px-1.5 py-0.2 rounded border border-white/[0.06] bg-black/40 text-zinc-400 group-hover:border-white/[0.12]">
                            {sec.badge}
                          </span>
                        )}
                      </a>
                    ))}
                  </nav>
                </div>
              </div>

              {/* Minimalist Escalation Card */}
              <div className="rounded-xl border border-white/[0.06] bg-zinc-950/70 p-4 space-y-2 text-xs">
                <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-amber-200/80">
                  <ClockIcon className="h-3.5 w-3.5 text-amber-300/80" /> Incident Escalation Hotlines
                </div>
                <div className="space-y-1 font-mono text-[10px] text-zinc-400 rounded-lg border border-white/[0.04] bg-black/50 p-2.5">
                  <div className="flex justify-between">
                    <span><LegalStatute href="https://www.cert-in.org.in/">CERT-In</LegalStatute>:</span>
                    <span className="text-zinc-200">incident@cert-in.org.in</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Toll Free:</span>
                    <span className="text-zinc-200">1800-11-4949</span>
                  </div>
                  <div className="flex justify-between">
                    <span><LegalStatute href="https://cybercrime.gov.in/">I4C Helpline</LegalStatute>:</span>
                    <span className="text-zinc-200">1930 (MHA Portal)</span>
                  </div>
                </div>
              </div>
            </div>
          </aside>

          {/* Right Column: Detailed Sections */}
          <main className="lg:col-span-8 xl:col-span-9 space-y-12">
            {/* Section 01: Executive Summary */}
            <section id="executive-summary" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">01.</span>
                  Executive Summary & Operational Mandate
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <p className="text-xs leading-relaxed text-zinc-400">
                <strong>Jane</strong> is an academic, defensive cyber threat intelligence platform developed for the
                Smart India Hackathon (Problem Statement 26151). Its architectural role is to assist authorized threat analysts
                by discovering, organizing, and mathematically correlating publicly visible threat indicators across the dark web
                without utilizing intrusive, destructive, or unauthorized technical techniques.
              </p>

              {/* Double Bezel Comparison Grid */}
              <div className="grid gap-3.5 sm:grid-cols-2 pt-1">
                <div className="rounded-xl border border-white/[0.06] bg-[#0d0d10] p-4 space-y-2">
                  <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-wider text-amber-200/90 font-medium">
                    <CheckCircle2Icon className="h-3.5 w-3.5 text-amber-300" /> Authorized Defensive Core
                  </div>
                  <ul className="space-y-1.5 text-[11px] text-zinc-400">
                    <li className="flex items-start gap-2">
                      <span className="text-amber-300/60 font-mono text-[10px]">•</span>
                      <span>Bounded, read-only collection of publicly reachable <code>.onion</code> endpoints.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-300/60 font-mono text-[10px]">•</span>
                      <span>Automated indicator extraction (crypto wallets, PGP fingerprints, CVE tags, handles).</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-300/60 font-mono text-[10px]">•</span>
                      <span>Cryptographic evidence preservation with SHA-256 digests and exact text offsets.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-300/60 font-mono text-[10px]">•</span>
                      <span>Multi-source infrastructure correlation and confidence-ranked lead scoring.</span>
                    </li>
                  </ul>
                </div>

                <div className="rounded-xl border border-white/[0.06] bg-[#0d0d10] p-4 space-y-2">
                  <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-wider text-zinc-300 font-medium">
                    <AlertCircleIcon className="h-3.5 w-3.5 text-zinc-400" /> Explicit Non-Goals & Boundaries
                  </div>
                  <ul className="space-y-1.5 text-[11px] text-zinc-400">
                    <li className="flex items-start gap-2">
                      <span className="text-zinc-500 font-mono text-[10px]">•</span>
                      <span>Not an offensive penetration testing tool, scanner, or exploit utility.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-zinc-500 font-mono text-[10px]">•</span>
                      <span>Not an automated judicial or law enforcement prosecution system.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-zinc-500 font-mono text-[10px]">•</span>
                      <span>Not a tool for purchasing goods, escrowing currency, or contacting actors.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-zinc-500 font-mono text-[10px]">•</span>
                      <span>Outputs represent preliminary leads for analyst review, never proof of guilt.</span>
                    </li>
                  </ul>
                </div>
              </div>
            </section>

            {/* Section 02: Legal & Institutional Posture */}
            <section id="legal-position" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">02.</span>
                  Legal and Institutional Posture
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <p className="text-xs leading-relaxed text-zinc-400">
                Jane operates strictly under a passive, defensive, and evidence-driven methodology.
                Routing traffic through Whonix or the Tor anonymity network is a transport layer security and operational security (OpSec)
                measure; <em>it does not create a separate legal jurisdiction, nor does it provide legal immunity from <LegalStatute>applicable cybersecurity laws</LegalStatute></em>.
              </p>

              <div className="rounded-xl border border-white/[0.06] bg-zinc-950/80 p-5 space-y-2.5 text-xs">
                <span className="font-mono text-[10px] uppercase tracking-wider text-amber-200/80">
                  Prerequisites for Operating Jane:
                </span>
                <ol className="space-y-2 text-[11px] text-zinc-400">
                  <li className="flex items-start gap-2.5">
                    <span className="font-mono text-amber-300/80 text-[10px]">1.</span>
                    <span><strong>Institutional Authorization:</strong> Deployment must be approved in writing by institutional mentors or designated supervisors.</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <span className="font-mono text-amber-300/80 text-[10px]">2.</span>
                    <span><strong>Bounded Scope:</strong> Operations must respect domain allowlists, page count caps (maximum 5), depth limits (depth = 1), and passive HTTP GET requests.</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <span className="font-mono text-amber-300/80 text-[10px]">3.</span>
                    <span><strong>Zero Exploitation:</strong> Discovered misconfigurations, software bugs, or exposed credentials must never be exploited or accessed.</span>
                  </li>
                </ol>
              </div>
            </section>

            {/* Section 03: IT Act 2000 */}
            <section id="it-act-2000" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">03.</span>
                  <LegalStatute href="https://www.indiacode.nic.in/indiacode/handle/123456789/1999?locale=en">Information Technology Act, 2000</LegalStatute> (India)
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <p className="text-xs leading-relaxed text-zinc-400">
                The <LegalStatute href="https://www.indiacode.nic.in/indiacode/handle/123456789/1999?locale=en">Information Technology Act, 2000</LegalStatute> (amended in 2008) is India's core legal framework governing electronic data,
                computer resources, and computer-related offenses. Jane's codebase incorporates architectural limitations specifically
                designed to prevent violations of statutory provisions:
              </p>

              <div className="grid gap-3.5 sm:grid-cols-2 pt-1">
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-medium text-amber-200/90"><LegalStatute>Section 43</LegalStatute> — Civil Liability</span>
                    <span className="font-mono text-[9px] px-1.5 py-0.2 rounded border border-white/[0.08] bg-white/[0.02] text-zinc-400">Civil Damages</span>
                  </div>
                  <p className="text-[11px] text-zinc-400 leading-relaxed">
                    Addresses accessing or securing access to a computer system or network without permission of the owner or person in charge under <LegalStatute>Section 43</LegalStatute>,
                    or downloading, copying, or extracting any data or information.
                  </p>
                  <div className="rounded border border-white/[0.04] bg-black/60 p-2 text-[10px] font-mono text-zinc-400">
                    Jane Control: Only unauthenticated, publicly broadcasted pages are read. Zero credential extraction or session theft.
                  </div>
                </div>

                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-medium text-amber-200/90"><LegalStatute>Section 66</LegalStatute> — Computer Offenses</span>
                    <span className="font-mono text-[9px] px-1.5 py-0.2 rounded border border-white/[0.08] bg-white/[0.02] text-zinc-400">Penal Code</span>
                  </div>
                  <p className="text-[11px] text-zinc-400 leading-relaxed">
                    Prescribes imprisonment up to three years or fines for acts described under <LegalStatute>Section 43</LegalStatute> performed dishonestly or fraudulently under <LegalStatute>Section 66</LegalStatute>,
                    including altering, destroying, or impairing utility.
                  </p>
                  <div className="rounded border border-white/[0.04] bg-black/60 p-2 text-[10px] font-mono text-zinc-400">
                    Jane Control: Purely read-only requests. No POST, PUT, DELETE, or state-altering requests permitted on target hosts.
                  </div>
                </div>
              </div>
            </section>

            {/* Section 04: CERT-In Directions 2022 */}
            <section id="cert-in-directions" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">04.</span>
                  <LegalStatute href="https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf">CERT-In Cybersecurity Directions (April 28, 2022)</LegalStatute>
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <p className="text-xs leading-relaxed text-zinc-400">
                <LegalStatute href="https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf">Direction No. 20(3)/2022-CERT-In</LegalStatute> issued under <LegalStatute>Section 70B(6)</LegalStatute> of the <LegalStatute>IT Act</LegalStatute> mandates cybersecurity incident response,
                system logging practices, and reporting obligations for corporate entities, service providers, intermediaries, and data centers in India.
              </p>

              <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-5 space-y-3 text-xs">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-white/[0.04] pb-2.5">
                  <span className="font-mono text-xs text-zinc-200 font-medium flex items-center gap-2">
                    <ClockIcon className="h-3.5 w-3.5 text-amber-300" />
                    Mandatory 6-Hour Incident Reporting Clock
                  </span>
                  <span className="font-mono text-[9px] text-amber-300/80 px-2 py-0.5 rounded border border-amber-400/20 bg-amber-400/[0.04]">
                    20 CYBERSECURITY INCIDENT CLASSES
                  </span>
                </div>

                <p className="text-[11px] text-zinc-400 leading-relaxed">
                  Covered entities must report designated security incidents—including unauthorized access to critical systems,
                  database leaks, ransomware activity, and fake services—to <LegalStatute href="https://www.cert-in.org.in/">CERT-In</LegalStatute> within <strong>six hours</strong> of noticing or being informed.
                </p>

                <div className="rounded-lg border border-white/[0.04] bg-black/40 p-3 space-y-1.5 text-[11px]">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-amber-200/90 font-medium">
                    Jane Operational Readiness Provisions:
                  </span>
                  <ul className="space-y-1 text-zinc-400 text-[10px]">
                    <li>• Synchronized NTP timestamps (UTC and IST) stored on all ingested network artifacts.</li>
                    <li>• Persistent audit trail preservation for investigation jobs, batch IDs, and request headers.</li>
                    <li>• Rapid institutional escalation pathway to enable institutional security contacts to satisfy the 6-hour reporting requirement if major infrastructure breaches are identified.</li>
                  </ul>
                </div>
              </div>
            </section>

            {/* Section 05: DPDP Act 2023 */}
            <section id="dpdp-act-2023" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">05.</span>
                  <LegalStatute href="https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf">Digital Personal Data Protection Act, 2023</LegalStatute> & Retention
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <p className="text-xs leading-relaxed text-zinc-400">
                During dark-web forum collection, Jane may process data relating to identifiable individuals (e.g., usernames, emails, messaging handles).
                India's <LegalStatute href="https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf">DPDP Act, 2023</LegalStatute> establishes statutory principles regarding Data Fiduciaries, purpose limitation, and mandatory erasure:
              </p>

              <div className="grid gap-3 sm:grid-cols-3 pt-1">
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-3.5 space-y-1">
                  <span className="font-mono text-[11px] text-zinc-200 font-medium">Data Minimization</span>
                  <p className="text-[10px] text-zinc-400">Collect solely the indicators required for threat correlation. Strip extraneous forum chatter and private message bodies.</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-3.5 space-y-1">
                  <span className="font-mono text-[11px] text-zinc-200 font-medium">Masking by Default</span>
                  <p className="text-[10px] text-zinc-400">Personally identifying handles and emails are masked in ordinary dashboard views to prevent accidental exposure.</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-3.5 space-y-1">
                  <span className="font-mono text-[11px] text-zinc-200 font-medium">7-Day Retention Limit</span>
                  <p className="text-[10px] text-zinc-400">Raw HTML captures are automatically purged after 7 days, maintaining only normalized, non-identifying IOCs.</p>
                </div>
              </div>
            </section>

            {/* Section 06: MHA & I4C */}
            <section id="mha-i4c" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">06.</span>
                  <LegalStatute>Ministry of Home Affairs (MHA)</LegalStatute> & <LegalStatute href="https://cybercrime.gov.in/">I4C Context</LegalStatute>
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-2 text-xs text-zinc-400 leading-relaxed">
                <p>
                  The <LegalStatute href="https://cybercrime.gov.in/">Indian Cyber Crime Coordination Centre (I4C)</LegalStatute>, under the <LegalStatute>Ministry of Home Affairs (MHA)</LegalStatute>, serves as the central
                  clearinghouse for cybercrime threat intelligence in India.
                </p>
                <p>
                  Jane aligns conceptually with national defensive priorities, but <em>Jane operators are academic researchers and do not hold statutory
                  investigative or law enforcement status</em>. Discovered criminal evidence must be referred to designated authorities through
                  formal institutional channels rather than unilateral action.
                </p>
              </div>
            </section>

            {/* Section 07: Operational Modes Matrix */}
            <section id="operating-modes" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">07.</span>
                  Operational Modes & State Matrix
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-zinc-950">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-white/[0.06] bg-white/[0.02] font-mono text-[10px] text-zinc-400 uppercase tracking-wider">
                    <tr>
                      <th className="px-3.5 py-3">Operating Mode</th>
                      <th className="px-3.5 py-3">Target Scope</th>
                      <th className="px-3.5 py-3">Permitted Operations</th>
                      <th className="px-3.5 py-3">Default Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.03] text-[11px]">
                    <tr className="hover:bg-white/[0.01]">
                      <td className="px-3.5 py-3 font-medium text-zinc-200">Passive OSINT Mode</td>
                      <td className="px-3.5 py-3 text-zinc-400">Public unauthenticated <code>.onion</code> sites</td>
                      <td className="px-3.5 py-3 text-zinc-400">Read-only HTTP GET, text extraction, graph construction</td>
                      <td className="px-3.5 py-3"><span className="font-mono text-[9px] px-1.5 py-0.5 rounded border border-amber-400/20 bg-amber-400/[0.05] text-amber-200/90">Default Enabled</span></td>
                    </tr>
                    <tr className="hover:bg-white/[0.01]">
                      <td className="px-3.5 py-3 font-medium text-zinc-200">Demo / Synthetic Mode</td>
                      <td className="px-3.5 py-3 text-zinc-400">Sanitized, simulated, or pre-captured datasets</td>
                      <td className="px-3.5 py-3 text-zinc-400">Offline presentation, zero network calls</td>
                      <td className="px-3.5 py-3"><span className="font-mono text-[9px] px-1.5 py-0.5 rounded border border-white/[0.08] bg-white/[0.02] text-zinc-400">Recommended for Demos</span></td>
                    </tr>
                    <tr className="hover:bg-white/[0.01]">
                      <td className="px-3.5 py-3 font-medium text-zinc-200">Controlled Lab Mode</td>
                      <td className="px-3.5 py-3 text-zinc-400">Owned private testnet infrastructure</td>
                      <td className="px-3.5 py-3 text-zinc-400">Simulated misconfigurations, Apache status verification</td>
                      <td className="px-3.5 py-3"><span className="font-mono text-[9px] px-1.5 py-0.5 rounded border border-white/[0.08] bg-white/[0.02] text-zinc-400">Requires Signed Scope</span></td>
                    </tr>
                    <tr className="hover:bg-white/[0.01]">
                      <td className="px-3.5 py-3 font-medium text-zinc-400">Active Probe Mode</td>
                      <td className="px-3.5 py-3 text-zinc-500">Live third-party servers</td>
                      <td className="px-3.5 py-3 text-zinc-500">Port scanning, dictionary path fuzzing</td>
                      <td className="px-3.5 py-3"><span className="font-mono text-[9px] px-1.5 py-0.5 rounded border border-red-500/20 bg-red-500/[0.05] text-red-300">Hard Restricted</span></td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>

            {/* Section 08: Permitted Activities */}
            <section id="permitted-activities" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">08.</span>
                  Permitted Activities (Passive OSINT Posture)
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="grid gap-3 sm:grid-cols-2 text-xs">
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1.5">
                  <span className="font-mono text-[11px] font-medium text-zinc-200">Strictly Bounded Crawling</span>
                  <p className="text-[11px] text-zinc-400 leading-relaxed">Crawl depth restricted to 1 (same-domain), maximum 5 pages per onion, with a mandatory 3-second per-domain rate limit to prevent load.</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1.5">
                  <span className="font-mono text-[11px] font-medium text-zinc-200">Public IOC Normalization</span>
                  <p className="text-[11px] text-zinc-400 leading-relaxed">Regular expression extraction of publicly posted Bitcoin/Monero addresses, PGP fingerprints, Tox/Telegram IDs, and CVE identifiers.</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1.5">
                  <span className="font-mono text-[11px] font-medium text-zinc-200">Passive Fingerprinting</span>
                  <p className="text-[11px] text-zinc-400 leading-relaxed">Analysis of server response headers, favicon Murmur3 hashes, and HTML template structural patterns without active probing.</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1.5">
                  <span className="font-mono text-[11px] font-medium text-zinc-200">MultiDiGraph Threat Modeling</span>
                  <p className="text-[11px] text-zinc-400 leading-relaxed">Synthesizing extracted indicators into weighted threat graph edges, linked to verifiable verbatim evidence quotes.</p>
                </div>
              </div>
            </section>

            {/* Section 09: Prohibited Activities */}
            <section id="prohibited-activities" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">09.</span>
                  Prohibited Intrusive Activities
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-5 space-y-3 text-xs">
                <span className="font-mono text-[10px] uppercase tracking-wider text-amber-200/80">
                  Absolute Technical Injunctions:
                </span>
                <div className="grid gap-2.5 sm:grid-cols-2 text-[11px] text-zinc-400">
                  <div className="flex items-start gap-2">
                    <span className="text-amber-300/80 font-mono text-[10px]">✕</span>
                    <span><strong>No Authentication:</strong> Zero account creation, password guessing, credential stuffing, or login sessions.</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-amber-300/80 font-mono text-[10px]">✕</span>
                    <span><strong>No Control Bypass:</strong> Zero CAPTCHA solving, rate-limit evasion, paywall bypassing, or access evasion.</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-amber-300/80 font-mono text-[10px]">✕</span>
                    <span><strong>No Active Probing:</strong> Zero port scanning, vulnerability fuzzing, or SQL injection tests against external targets.</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-amber-300/80 font-mono text-[10px]">✕</span>
                    <span><strong>No Actor Engagement:</strong> Zero messaging dark-market vendors, forum users, or buying illicit goods.</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-amber-300/80 font-mono text-[10px]">✕</span>
                    <span><strong>No Crypto Transfers:</strong> Zero wallet funding, transactions, micro-payments, or escrow deposits.</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-amber-300/80 font-mono text-[10px]">✕</span>
                    <span><strong>No Media Auto-Downloads:</strong> Zero automatic downloading or rendering of binaries, archives, or executable scripts.</span>
                  </div>
                </div>
              </div>
            </section>

            {/* Section 10: Sensitive Path Blacklist */}
            <section id="sensitive-endpoints" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">10.</span>
                  Sensitive Path Probing Blacklist
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <p className="text-xs text-zinc-400 leading-relaxed">
                Automated vulnerability scanners often request sensitive misconfiguration paths. On live third-party servers,
                issuing these requests without authorization constitutes potential unauthorized access under <LegalStatute>Section 43</LegalStatute> and <LegalStatute>Section 66</LegalStatute> of the <LegalStatute>Information Technology Act</LegalStatute>.
                Jane's crawler has these paths <strong>hardcoded into its request refusal filter</strong>:
              </p>

              <div className="rounded-xl border border-white/[0.06] bg-black/60 p-4 font-mono text-xs text-zinc-300 space-y-1.5">
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider">// HARDCODED BLOCKLIST IN collector/discovery.py</div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px] text-zinc-300">
                  <div>• /.git/HEAD</div>
                  <div>• /.env</div>
                  <div>• /server-status?auto</div>
                  <div>• /phpinfo.php</div>
                  <div>• /admin</div>
                  <div>• /wp-login.php</div>
                  <div>• /backup.zip</div>
                  <div>• /database.sql</div>
                  <div>• /config.json</div>
                </div>
              </div>
              <p className="text-[10px] text-zinc-500 font-mono">
                * Path testing is restricted exclusively to Controlled Lab Mode on owned infrastructure.
              </p>
            </section>

            {/* Section 11: Controlled Lab Mode Protocol */}
            <section id="authorized-lab-mode" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">11.</span>
                  Controlled Lab Mode Activation Protocol
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-2 text-xs text-zinc-400 leading-relaxed">
                <p>
                  To validate advanced attribution heuristics (such as server banner matching or simulated misconfiguration detection),
                  Controlled Lab Mode requires:
                </p>
                <ul className="space-y-1 text-[11px] text-zinc-300">
                  <li>• <strong>Signed Authorization Record:</strong> Documentation designating specific target IP/domain, test duration, and responsible operator.</li>
                  <li>• <strong>Default-Deny Scope:</strong> Only explicitly allowlisted laboratory targets may be contacted.</li>
                  <li>• <strong>Watermarked Outputs:</strong> All exported artifacts are watermarked with: <em>“AUTHORIZED LAB SIMULATION — NOT REAL-WORLD TARGET”</em>.</li>
                </ul>
              </div>
            </section>

            {/* Section 12: 3-Tier Attribution Taxonomy */}
            <section id="attribution-taxonomy" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">12.</span>
                  3-Tier Attribution Taxonomy & Linguistic Cautions
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="grid gap-3.5 sm:grid-cols-3">
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1.5">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-amber-200/90 font-medium">Level 1: Observed Facts</span>
                  <p className="text-[11px] font-medium text-zinc-200">Direct Captured Evidence</p>
                  <p className="text-[10px] text-zinc-400">Verbatim regex matches, SHA-256 hashes, exact text offsets, and raw HTTP response headers. 100% ground truth.</p>
                </div>

                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1.5">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-300 font-medium">Level 2: Mathematical Inferences</span>
                  <p className="text-[11px] font-medium text-zinc-200">Computed Correlations</p>
                  <p className="text-[10px] text-zinc-400">Stylometry cosine distance, favicon Murmur3 overlap, and shared wallet clustering. Probabilistic; requires corroboration.</p>
                </div>

                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1.5">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 font-medium">Level 3: Analytical Hypotheses</span>
                  <p className="text-[11px] font-medium text-zinc-200">Analyst Interpretations</p>
                  <p className="text-[10px] text-zinc-400">Theories linking Persona A to Actor Group B. Candidate leads subject to qualified human verification.</p>
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-2 text-xs">
                <span className="font-mono text-[10px] uppercase tracking-wider text-amber-200/80 font-medium">
                  Forensic Lexicon Standard:
                </span>
                <div className="grid gap-3 sm:grid-cols-2 text-[11px]">
                  <div className="rounded border border-white/[0.04] bg-black/40 p-2.5 space-y-1">
                    <span className="text-zinc-200 font-medium">Mandatory Cautious Terminology:</span>
                    <ul className="text-[10px] text-zinc-400 space-y-0.5">
                      <li>• "Candidate attribution lead"</li>
                      <li>• "Observed indicator correlation"</li>
                      <li>• "Candidate origin-IP requires external corroboration"</li>
                    </ul>
                  </div>
                  <div className="rounded border border-white/[0.04] bg-black/40 p-2.5 space-y-1">
                    <span className="text-zinc-200 font-medium">Strictly Prohibited Assertions:</span>
                    <ul className="text-[10px] text-zinc-400 space-y-0.5">
                      <li>• "Confirmed criminal identity"</li>
                      <li>• "Conclusive proof of ownership"</li>
                      <li>• "Guaranteed physical geolocation of operator"</li>
                    </ul>
                  </div>
                </div>
              </div>
            </section>

            {/* Section 13: Content Safety & Quarantine */}
            <section id="quarantine-protocol" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">13.</span>
                  Content Safety & Zero-Tolerance Quarantine Protocol
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-5 space-y-3 text-xs text-zinc-400 leading-relaxed">
                <div className="flex items-center gap-2 font-mono text-xs text-amber-200/90 font-medium">
                  <ShieldAlertIcon className="h-4 w-4 text-amber-300" />
                  Zero-Tolerance Abort Circuit:
                </div>
                <ol className="space-y-2 text-[11px] text-zinc-400">
                  <li className="flex items-start gap-2.5">
                    <span className="font-mono text-amber-300/80 text-[10px]">1.</span>
                    <span><strong>Immediate Crawl Termination:</strong> If unlawful or harmful content triggers are detected, the crawler halts within 50 milliseconds.</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <span className="font-mono text-amber-300/80 text-[10px]">2.</span>
                    <span><strong>Zero File Storage:</strong> The raw page text, media, or attachments are <em>never written to persistent disk or database tables</em>.</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <span className="font-mono text-amber-300/80 text-[10px]">3.</span>
                    <span><strong>Minimal Metadata Preservation:</strong> Only the source URL, timestamp, and alert identifier are preserved in an encrypted audit log.</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <span className="font-mono text-amber-300/80 text-[10px]">4.</span>
                    <span><strong>Institutional Escalation:</strong> The incident is escalated to the institutional supervisor for formal reporting to <LegalStatute href="https://www.cert-in.org.in/">CERT-In</LegalStatute> or <LegalStatute href="https://cybercrime.gov.in/">I4C</LegalStatute>.</span>
                  </li>
                </ol>
              </div>
            </section>

            {/* Section 14: Evidence Integrity & Reports */}
            <section id="evidence-integrity" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">14.</span>
                  Cryptographic Evidence Integrity & Forensic Exports
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <p className="text-xs text-zinc-400 leading-relaxed">
                Digital evidence gathered through Jane is cryptographically structured to comply with electronic records admissibility standards under <LegalStatute>Section 65B of the Indian Evidence Act, 1872</LegalStatute> (and corresponding <LegalStatute>Section 63 of the Bharatiya Sakshya Adhiniyam, 2023</LegalStatute>), preserving strict contemporaneous hashes and an unbroken audit chain:
              </p>

              <div className="grid gap-3 sm:grid-cols-2 text-xs">
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1">
                  <span className="font-mono text-[11px] font-medium text-zinc-200">SHA-256 Invariant</span>
                  <p className="text-[11px] text-zinc-400">All captured artifacts are cryptographically hashed upon arrival. Recalculation verifies data immutability over time.</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1">
                  <span className="font-mono text-[11px] font-medium text-zinc-200">Verbatim Bounding Quotes</span>
                  <p className="text-[11px] text-zinc-400">Extracted IOCs store exact character start/end offsets and 100-character bounding quotes within raw HTML drops.</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1">
                  <span className="font-mono text-[11px] font-medium text-zinc-200">Isolated Annotations</span>
                  <p className="text-[11px] text-zinc-400">Analyst tags and notes are isolated in separate relational tables, ensuring pristine source captures remain unaltered.</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-4 space-y-1">
                  <span className="font-mono text-[11px] font-medium text-zinc-200">Export Audit Trail</span>
                  <p className="text-[11px] text-zinc-400">Every exported PDF, CSV, or graph JSON logs the analyst username, timestamp, and report hash in <code>audit_logs</code>.</p>
                </div>
              </div>
            </section>

            {/* Section 15: Incident Escalation Workflow */}
            <section id="incident-escalation" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">15.</span>
                  Incident Escalation Workflow
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="space-y-2 text-xs">
                {[
                  { step: "01", title: "Crawl Halt", desc: "Halt crawler via Emergency Kill Switch immediately upon detecting prohibited material or out-of-scope targets." },
                  { step: "02", title: "Metadata Isolation", desc: "Preserve target URL, timestamp, and SHA-256 checksum in an encrypted log. Do not export raw content." },
                  { step: "03", title: "Supervisor Notification", desc: "Inform the institutional Faculty Advisor and Security Officer via official communication channels." },
                  { step: "04", title: "Zero Contact", desc: "Operators must not contact target hosts, victims, suspects, media, or third-party entities directly." },
                  {
                    step: "05",
                    title: "Formal Filing",
                    desc: (
                      <>
                        Institutional leadership evaluates and files mandatory notifications with{" "}
                        <LegalStatute href="https://www.cert-in.org.in/">CERT-In</LegalStatute> or statutory law enforcement agencies within the 6-hour regulatory window mandated under{" "}
                        <LegalStatute>Section 70B</LegalStatute>.
                      </>
                    ),
                  },
                ].map((item) => (
                  <div key={item.step} className="flex items-start gap-3.5 rounded-xl border border-white/[0.06] bg-zinc-950 p-3.5">
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-amber-400/20 bg-amber-400/[0.06] font-mono text-[10px] text-amber-200/90 font-medium">
                      {item.step}
                    </span>
                    <div>
                      <span className="font-medium text-zinc-200">{item.title}:</span>
                      <p className="text-[11px] text-zinc-400 mt-0.5">{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* Section 16: Technical Safeguards & Configuration Defaults */}
            <section id="technical-safeguards" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">16.</span>
                  System Safeguards & Environment Configuration
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="relative rounded-xl border border-white/[0.06] bg-black p-4 font-mono text-xs">
                <Button
                  size="sm"
                  variant="ghost"
                  className="absolute right-3 top-3 h-7 gap-1.5 text-[10px] text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.06] rounded-md border border-white/[0.06]"
                  onClick={copyConfigToClipboard}
                >
                  {copiedConfig ? <CheckIcon className="h-3 w-3 text-amber-300" /> : <CopyIcon className="h-3 w-3" />}
                  {copiedConfig ? "Copied" : "Copy Configuration"}
                </Button>
                <pre className="overflow-x-auto text-[11px] text-zinc-400 leading-relaxed pr-24">
                  {safeConfigCode}
                </pre>
              </div>
            </section>

            {/* Section 17: Operator Ethical Acknowledgement */}
            <section id="operator-pledge" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">17.</span>
                  Operator Ethical Acknowledgement
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="rounded-xl border border-white/[0.06] bg-zinc-950 p-5 space-y-4">
                <span className="font-mono text-[10px] uppercase tracking-wider text-amber-200/80 block">
                  Mandatory Operational Affirmations:
                </span>

                <div className="space-y-2.5 text-xs text-zinc-300">
                  <label className="flex items-start gap-3 cursor-pointer hover:text-zinc-100 transition-colors">
                    <input
                      type="checkbox"
                      checked={pledgeChecked.scope}
                      onChange={(e) => setPledgeChecked({ ...pledgeChecked, scope: e.target.checked })}
                      className="mt-0.5 rounded border-white/[0.2] bg-zinc-900 text-amber-400 focus:ring-amber-400/30"
                    />
                    <span>I confirm that this investigation is within my authorized academic or institutional scope.</span>
                  </label>

                  <label className="flex items-start gap-3 cursor-pointer hover:text-zinc-100 transition-colors">
                    <input
                      type="checkbox"
                      checked={pledgeChecked.passive}
                      onChange={(e) => setPledgeChecked({ ...pledgeChecked, passive: e.target.checked })}
                      className="mt-0.5 rounded border-white/[0.2] bg-zinc-900 text-amber-400 focus:ring-amber-400/30"
                    />
                    <span>I will use Jane solely for passive, read-only collection from publicly reachable, unauthenticated pages unless explicit written authorization exists.</span>
                  </label>

                  <label className="flex items-start gap-3 cursor-pointer hover:text-zinc-100 transition-colors">
                    <input
                      type="checkbox"
                      checked={pledgeChecked.noBypass}
                      onChange={(e) => setPledgeChecked({ ...pledgeChecked, noBypass: e.target.checked })}
                      className="mt-0.5 rounded border-white/[0.2] bg-zinc-900 text-amber-400 focus:ring-amber-400/30"
                    />
                    <span>I will NOT bypass access controls, authenticate to third-party services, exploit systems, contact actors, or conduct cryptocurrency transactions.</span>
                  </label>

                  <label className="flex items-start gap-3 cursor-pointer hover:text-zinc-100 transition-colors">
                    <input
                      type="checkbox"
                      checked={pledgeChecked.leadsOnly}
                      onChange={(e) => setPledgeChecked({ ...pledgeChecked, leadsOnly: e.target.checked })}
                      className="mt-0.5 rounded border-white/[0.2] bg-zinc-900 text-amber-400 focus:ring-amber-400/30"
                    />
                    <span>I understand that Jane outputs are analytical leads requiring human corroboration, not conclusive legal proofs of identity or guilt.</span>
                  </label>

                  <label className="flex items-start gap-3 cursor-pointer hover:text-zinc-100 transition-colors">
                    <input
                      type="checkbox"
                      checked={pledgeChecked.quarantine}
                      onChange={(e) => setPledgeChecked({ ...pledgeChecked, quarantine: e.target.checked })}
                      className="mt-0.5 rounded border-white/[0.2] bg-zinc-900 text-amber-400 focus:ring-amber-400/30"
                    />
                    <span>I will immediately halt and escalate suspected prohibited material, critical infrastructure attacks, or out-of-scope discoveries through institutional channels.</span>
                  </label>
                </div>

                <div className="pt-3 flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-white/[0.06]">
                  <span className={`font-mono text-[11px] ${allPledged ? "text-amber-200/90" : "text-zinc-500"}`}>
                    {allPledged ? "✓ All 5 Affirmations Acknowledged" : "Affirm all 5 declarations to proceed"}
                  </span>
                  <Link href="/investigations">
                    <Button
                      size="sm"
                      disabled={!allPledged}
                      className="rounded-full border border-amber-400/30 bg-amber-400/[0.08] px-5 py-2 text-xs font-medium text-amber-200/90 shadow-[inset_0_1px_1px_rgba(245,158,11,0.2)] hover:bg-amber-400/[0.14] disabled:opacity-40 disabled:pointer-events-none transition-all duration-300"
                    >
                      <ShieldCheckIcon className="h-3.5 w-3.5 mr-2 text-amber-300" />
                      Proceed to Investigation Cockpit
                    </Button>
                  </Link>
                </div>
              </div>
            </section>

            {/* Section 18: Statutory Citations & Primary Legal Sources */}
            <section id="statutory-citations" className="space-y-4 scroll-mt-24">
              <div className="flex items-baseline justify-between border-b border-white/[0.08] pb-3">
                <h2 className="text-lg font-medium tracking-tight text-zinc-100 flex items-center gap-2.5">
                  <span className="font-mono text-xs text-amber-300/80">08.</span>
                  Statutory Citations & References
                </h2>
                <a href="#top" onClick={scrollToTop} className="font-mono text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  TOP <ArrowUpIcon className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="grid gap-2.5 sm:grid-cols-2">
                {[
                  {
                    title: "Information Technology Act, 2000",
                    url: "https://www.indiacode.nic.in/indiacode/handle/123456789/1999?locale=en",
                    desc: (
                      <>
                        Official gazette text on India Code (<LegalStatute>Section 43</LegalStatute>, <LegalStatute>Section 66</LegalStatute>, <LegalStatute>Section 69</LegalStatute>, <LegalStatute>Section 70B</LegalStatute> civil/criminal provisions).
                      </>
                    ),
                  },
                  {
                    title: "CERT-In Directions No. 20(3)/2022",
                    url: "https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf",
                    desc: (
                      <>
                        Official gazette directions on 6-hour cybersecurity incident reporting and mandatory log retention under <LegalStatute>Section 70B(6)</LegalStatute>.
                      </>
                    ),
                  },
                  {
                    title: "Digital Personal Data Protection Act, 2023",
                    url: "https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf",
                    desc: "Ministry of Electronics & Information Technology (MeitY) gazette publication on data minimization and erasure.",
                  },
                  {
                    title: "CERT-In Regulatory Commentary (Obhan)",
                    url: "https://obhanmason.com/blog/an-overview-on-the-cert-in-cyber-security-directions-2022/",
                    desc: "Authoritative legal analysis of cybersecurity directions and compliance thresholds.",
                  },
                ].map((item, idx) => (
                  <a
                    key={idx}
                    href={item.url}
                    target="_blank"
                    rel="noreferrer"
                    className="group rounded-xl border border-white/[0.06] bg-zinc-950 p-3.5 hover:border-amber-400/30 transition-all duration-200"
                  >
                    <div className="flex items-center justify-between text-xs font-medium text-zinc-200 group-hover:text-amber-200 transition-colors">
                      <span className="underline decoration-amber-400/40 decoration-1 underline-offset-[3px]">{item.title}</span>
                      <span className="font-mono text-[10px] text-zinc-500 group-hover:translate-x-0.5 transition-transform">↗</span>
                    </div>
                    <p className="text-[10px] text-zinc-400 mt-1">{item.desc}</p>
                  </a>
                ))}
              </div>
            </section>

            {/* Footer Institutional Signature */}
            <div className="rounded-xl border border-white/[0.06] bg-zinc-950/40 p-6 text-center text-xs space-y-1.5">
              <p className="font-mono text-[10px] uppercase tracking-wider text-amber-200/80 font-medium">
                Jane — Dark Web Threat Intelligence & Attribution Cockpit
              </p>
              <p className="text-[11px] text-zinc-500 max-w-xl mx-auto leading-relaxed">
                Operating doctrine enforced across all autonomous pipelines. Compliance with applicable Indian law,
                statutory proportionality, and human analytical review is mandatory for all deployments.
              </p>
            </div>
          </main>
        </div>
      </div>
    </AppShell>
  );
}
