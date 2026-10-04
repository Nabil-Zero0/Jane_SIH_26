# Jane: Autonomous Dark Web Threat Intelligence & Attribution Platform

> ### Academic & Defensive Research Notice: Smart India Hackathon 2026 (SIH 26)
> **This project is developed strictly for research purposes for Smart India Hackathon 2026 (SIH 26).**  
> **This platform actually scrapes the dark web via automated Tor hidden-service crawlers to research de-anonymization techniques for SIH 26.**  
> **All crawlers, extractors, and graph pipelines exist exclusively for academic evaluation, student research, and defensive threat intelligence for SIH 26.**  
> **This repository contains only source code. No real-world illicit databases, contraband files, or compromised credentials are hosted in this repository.**

---

## The Problem and Context (SIH 26 Problem Statement 26151)

This project targets Problem Statement 26151 for the National Technical Research Organisation (NTRO) in the Smart India Hackathon 2026 (SIH 26).

Dark web operators rely on Tor onion-routing to hide their network locations while trading in stolen credentials, ransomware tools, and illegal commodities. At the network level, Tor cryptographically conceals IP addresses. But threat actors still make human errors: they reuse PGP keys across forums, post text with idiosyncratic function-word habits, leave web servers misconfigured, and reuse clearweb usernames.

Traditional scraping tools create two severe risks for law enforcement and intelligence analysts:
1. **Investigator Exposure**: Scraping onion services directly from an analyst workstation risks leaking DNS queries, system fingerprints, and clearweb IPs to hostile operators.
2. **Attribution Drift**: General-purpose AI crawlers often fabricate connections or confuse co-occurring forum users with criminal co-conspirators.

Jane solves both problems. It executes dark web scraping through an air-gapped virtual machine diode, extracts deterministic forensic evidence with exact character offsets, and cross-correlates infrastructure fingerprints to de-anonymize dark web actors strictly for SIH 26 academic research.

---

## How Jane Scrapes the Dark Web for SIH 26 Research

Jane is an operational prototype built to scrape dark web onion sites under strict safety controls for SIH 26 research. The collection workflow runs as follows:

```
[Analyst Investigation Query]
              │
              ▼
    [Query Planner (Fanout)]
              │
              ▼ (Atomic File Transfer via VirtualBox Shared Folder)
┌────────────────────────────────────────────────────────┐
│  Whonix-Workstation VM (Air-Gapped Collection Diode)   │
│                                                        │
│  1. Multi-Engine Onion Discovery (Ahmia, Torch, Tor66) │
│  2. BFS Tor DOM Crawler (SOCKS5 10.152.152.10:9050)    │
│  3. Locksmith Probe (Favicon mmh3 & /server-status)    │
└────────────────────────────────────────────────────────┘
              │
              ▼ (Batch JSON Drops to drop/incoming/)
┌────────────────────────────────────────────────────────┐
│  Host Analysis Engine                                  │
│                                                        │
│  1. Sentence-Bounded Chunker (SHA-256 Digests)         │
│  2. Entity Extractor (25+ Regex Types & Confidence)    │
│  3. Crypto Sanctions Screening (OFAC / ChainQuery)     │
│  4. Side-Channel Correlator (Shodan InternetDB API)    │
│  5. Forensic Stylometry Engine (Burrows' Delta)        │
│  6. Authoritative Threat Graph Synthesis               │
└────────────────────────────────────────────────────────┘
              │
              ▼
   [Next.js 16 Dashboard & Court-Admissible Dossier Export]
```

1. **Air-Gapped Tor Scraping Gateway**: All live dark web scraping runs inside an isolated Whonix-Workstation virtual machine. The crawler routes traffic through the Tor gateway at `10.152.152.10:9050`. The host machine never touches the Tor network directly, eliminating any risk of DNS or IP leakage during SIH 26 experiments.
2. **Multi-Engine Dark Web Discovery**: Rather than relying on static onion directories, the collection module queries Ahmia, Torch, Tor66, and OnionLand in parallel to discover relevant hidden services for each hunt query.
3. **Locksmith Side-Channel Triangulation**: While scraping onion services, Jane probes for server misconfigurations. It computes 32-bit MurmurHash3 signatures of site favicons (matching Shodan's indexing algorithm) and checks Apache `/server-status` disclosures to pinpoint the origin clearweb server behind the onion service.
4. **Sentence-Bounded Evidence Slices**: All scraped HTML text is sliced into immutable chunks with exact character offsets and SHA-256 hashes. Every claim in the generated threat graph points directly back to a verifiable quote in the preserved page text.
5. **Mathematical Stylometry**: Threat actors frequently rebrand their monikers. Jane calculates Burrows' Delta z-scores across the 20 most frequent English function words (such as *the, and, of, with, to*) along with 6D stylistic vectors to match anonymous authors across distinct onion forums.
6. **Clearnet OSINT Expansion**: Extracted handles and emails trigger automated background searches via local Maigret scanners, linking dark web personas to clearweb footprints.

---

## Core System Architecture

Jane is organized into four distinct tiers:

### 1. Air-Gapped Collection Subsystem
* Runs autonomously inside a Whonix Debian virtual machine.
* Communicates with the host system exclusively through unidirectional file drops on a shared directory.
* Preserves raw HTML documents, HTTP response headers, and asset signatures for legal admissibility.

### 2. Analytical & Attribution Core
* **Entity Extraction**: Over 2,300 lines of pre-compiled regular expressions identifying cryptocurrency wallets (BTC, ETH, XMR), PGP key blocks, Telegram and Session handles, CVE identifiers, and server hashes.
* **Confidence Scoring**: Replaces static guesswork with a calibrated confidence ladder (0.50 to 0.98) based on format rigidity and cryptographic checksums.
* **Graph Modeling**: Builds authoritative multi-relational graphs using canonical node types (`Actor`, `Marketplace`, `Product`) and canonical edge types (`OPERATES_ON`, `SELLS`, `shares_identifier`, `trust`).

### 3. Three-Tier Relational Intelligence Datastore (SQLite WAL)
Jane stores all operational records in an embedded SQLite database (`data/jane.db`) structured across 42 relational tables and 8 pre-compiled forensic views:
* **Baseline Pipeline Layer (16 Tables)**: Stores raw search runs, crawled onion pages, sentence-bounded evidence chunks, and graph caches.
* **Canonical V2 Entity Layer (15 Tables)**: Normalizes actors, marketplaces, products, clearnet accounts, and vouching networks into deduplicated entities.
* **Structured Intelligence Layer (11 Tables)**: Tracks pricing observations, multi-marketplace distribution, attribution hypotheses, stylometry findings, and OSINT targets.
* **Analytical Views (8 Views)**: Pre-compiled SQL views providing instant aggregation for actor dossiers, commodity pricing trends, and infrastructure links.

### 4. User Interface & Forensic Workbench
* **Interactive Next.js 16 Web Application**: Built with React 19 and Tailwind CSS, featuring full-screen relationship canvases powered by Cytoscape.js, `@xyflow/react`, and Mermaid.js.
* **Live SSE Progress Tracking**: Real-time server-sent event updates during active scraping and extraction stages.
* **SQL Studio & Natural Language Query Copilot**: Interactive workbench allowing investigators to run custom SQL queries or translate plain-English questions into safe SQL statements.
* **Court-Admissible Dossier Exporter**: Generates two-pass PDF reports with ReportLab, raw JSON dumps, and multi-table CSV packages.

---

## Research Scope & Compliance (SIH 26)

Because this system actually scrapes the dark web for SIH 26 academic research, it is built with explicit safeguards:

* **Strictly Passive Collection**: Jane collects only publicly accessible dark web data. It performs zero unauthorized access, zero brute-force attempts, and zero automated interaction with forum users.
* **Indian Statutory Alignment**: Designed to comply with:
  * **Information Technology Act, 2000**: Operates within passive research boundaries (Sections 43 and 66 compliance).
  * **CERT-In Directions, 2022**: Maintains tamper-evident audit logs and timestamped chains of custody.
  * **Digital Personal Data Protection Act (DPDPA), 2023**: Restricts collection strictly to threat indicators and contraband metadata, preventing indiscriminate collection of bystander data.
  * **Bharatiya Sakshya Adhiniyam (BSA), 2023 Section 63**: Produces electronic records accompanied by SHA-256 cryptographic hashes and sentence-bounded evidence offsets.
* **Isolated Test Environments**: Test suites run against isolated temporary databases (`tests/conftest.py`), ensuring test processes cannot contaminate production datasets.

---

## Quickstart & Local Setup

### Prerequisites
* Python 3.11 or 3.12
* Node.js 18+ and npm
* Optional for live scraping: VirtualBox with Whonix-Workstation configured with shared folder `/media/sf_Jane_SIH_26/jane/data`

### 1. Clone the Repository
```bash
git clone https://github.com/Nabil-Zero0/Jane_SIH_26.git
cd Jane_SIH_26
```

### 2. Backend Installation
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Frontend Installation
```bash
cd jane/frontend
npm install
cd ../..
```

### 4. Running the Application
Start the backend API server and frontend interface:
```powershell
# In terminal 1 (Backend API on http://127.0.0.1:8080):
python jane/web/server.py

# In terminal 2 (Frontend Interface on http://localhost:3000):
cd jane/frontend
npm run dev
```

Navigate to `http://localhost:3000` to access the investigation dashboard.

---

## Academic Citation & Project Team

Developed as an official competition entry for the **Smart India Hackathon 2026 (SIH 26)** under the cybersecurity and threat intelligence track (NTRO Problem Statement 26151).

All investigations, dark web scraping runs, and entity correlation logic documented in this project are conducted exclusively for defensive evaluation, law enforcement prototype research, and educational review for SIH 26.
