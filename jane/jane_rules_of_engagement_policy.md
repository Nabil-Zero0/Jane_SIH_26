# Jane — Rules of Engagement, Legal Compliance & Responsible Use Policy

> **Status:** Academic and defensive-use policy for the Jane prototype  
> **Audience:** Students, researchers, faculty supervisors, institutional security teams, and authorized analysts  
> **Default posture:** Passive, read-only, human-reviewed, and scope-limited

## 1. Purpose and Scope

Jane is an academic, defensive open-source intelligence (OSINT) and cyber-threat-intelligence prototype intended for Smart India Hackathon / NTRO-oriented evaluation and controlled research.

Jane supports the collection and organization of publicly reachable information, extraction of public indicators of compromise (IOCs), evidence-linked relationship mapping, stylometric comparison, infrastructure correlation, and confidence-ranked investigative leads.

Jane is **not** an autonomous prosecution, identification, or law-enforcement system. Its outputs are analytical leads for qualified human review. Jane must not be used to make final claims of identity, criminal liability, guilt, or legal responsibility.

This policy applies to:

- All Jane operators, developers, evaluators, supervisors, and administrators.
- All collection, processing, analysis, storage, visualization, export, and sharing performed through Jane.
- Live investigations, demonstrations, test fixtures, mock data, and authorized laboratory exercises.

## 2. Legal and Institutional Position

Jane may be used only when the activity is:

1. **Authorized** by the relevant institution, system owner, or other lawful authority.
2. **Passive and defensive** unless a separate written authorization expressly permits a defined laboratory activity.
3. **Within approved scope**, including approved targets, methods, dates, operators, data types, and reporting channels.
4. **Consistent with applicable law, institutional rules, service terms, and professional duties.**

Student status, academic research, Smart India Hackathon participation, or an NTRO-related problem statement does **not** itself authorize access to restricted systems, circumvention of controls, intrusive testing, collection of non-public data, or contact with suspected threat actors.

Tor routing or use of a Whonix VM is a security-control measure, not a legal exemption. An `.onion` address is not proof that a target is public, lawful to access, safe to download from, or within the operator’s permitted scope.

## 3. Relevant Indian Legal Framework

This section identifies relevant legal and institutional context. It is not a complete legal opinion, and applicability depends on facts, jurisdiction, authorization, the nature of the system, and the data involved.

### 3.1 Information Technology Act, 2000

The Information Technology Act, 2000 contains provisions relevant to unauthorized access, damage, extraction, disruption, and other conduct involving computer resources. In particular, section 43 addresses specified acts involving a computer, computer system, or computer network without permission of the owner or person in charge; section 66 addresses certain acts described in section 43 when done dishonestly or fraudulently, subject to the statutory requirements.

Jane therefore adopts the following conservative rule:

- Public reachability does not automatically establish permission for every technical action.
- Reading a publicly reachable page in a normal, non-intrusive manner must not be treated as authorization to bypass controls or probe sensitive paths.
- Authorization must be documented before any activity that goes beyond passive collection.
- Operators must not rely on this policy to decide that a particular activity is lawful; the institution’s legal or compliance personnel should assess the specific facts.

**Primary source:** [India Code — Information Technology Act, 2000](https://www.indiacode.nic.in/indiacode/handle/123456789/1999?locale=en)

### 3.2 CERT-In Directions, 2022

The CERT-In Directions dated 28 April 2022 were issued under the Information Technology Act framework and address information-security practices, incident prevention, response, reporting, and related obligations.

The Directions apply to covered entities and situations within their scope; they should not be described as imposing identical obligations on every student, researcher, or prototype. Whether an institution or operator is covered, and which requirements apply, must be determined from the current text, the entity’s status, the incident facts, and institutional legal advice.

Relevant operational principles include:

- Maintain reliable logs and investigation records where required by applicable obligations or institutional policy.
- Preserve relevant records when an incident or suspected incident is identified.
- Use the institution’s established incident-response and reporting channels.
- Do not assume that Jane’s internal logging alone satisfies every statutory retention, reporting, or cooperation requirement.

**Primary source:** [CERT-In Directions under section 70B — 28 April 2022](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf)  
**CERT-In institutional context:** [CERT-In official website](https://www.cert-in.org.in/)

### 3.3 Digital Personal Data Protection Act, 2023

Jane may encounter information that identifies, relates to, or can reasonably be linked with an individual, including usernames, email addresses, messaging handles, IP-related information, writing samples, and combined identifiers. Processing may include collection, recording, organization, storage, retrieval, analysis, combination, sharing, export, and deletion.

The Digital Personal Data Protection Act, 2023 defines concepts including personal data, digital personal data, processing, Data Fiduciary, and Data Processor. The Act’s commencement is subject to government notification and staged commencement provisions; the institution must verify which provisions are in force at the time and in the relevant circumstances.

Jane should therefore apply privacy-by-design safeguards even where a specific statutory obligation is uncertain:

- Establish and document a lawful and institutionally approved purpose.
- Minimize collection and retention.
- Avoid collecting information that is unnecessary for the approved research objective.
- Restrict access to authorized personnel.
- Mask or pseudonymize personal data in dashboards and reports by default.
- Assess whether a legal basis, notice, consent, exemption, security measure, breach process, or other requirement applies before deployment.
- Avoid sending live captures or personal data to third-party services or LLM providers without documented approval.

**Primary sources:** [India Code — Digital Personal Data Protection Act, 2023](https://www.indiacode.nic.in/indiacode/handle/123456789/22037?view_type=browse) and [MeitY copy of the Act](https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf)

### 3.4 I4C and Ministry of Home Affairs Context

The Indian Cybercrime Coordination Centre (I4C) and the Ministry of Home Affairs form part of India’s institutional cybercrime-response context. Their existence or involvement in a problem statement does not confer investigative powers, access rights, operational authorization, or reporting authority on Jane’s developers, students, or users.

Any referral to a government body must occur through an approved institutional and legal process. The institution should determine whether a matter should be reported, to whom, and with what information.

## 4. Permitted Activities

Subject to written institutional approval and applicable law, Jane may be used for:

- Publicly reachable, unauthenticated, **read-only** collection of `.onion` pages.
- Strictly bounded crawling with depth, page-count, request-rate, timeout, and response-size limits.
- Collection of URLs, timestamps, status codes, permitted headers, cleaned text, content hashes, and minimal evidence metadata.
- Extraction and normalization of publicly exposed IOCs, such as wallet strings, PGP fingerprints, public handles, CVEs, IP addresses, and file hashes.
- Passive metadata and template analysis, including favicon and publicly returned header information, when performed without intrusive requests.
- Evidence-linked graph construction, confidence-ranked analysis, and analyst review.
- Controlled demonstrations using synthetic, historical, or institutionally approved datasets.
- Advanced testing only against owned or explicitly authorized targets under the Authorized Lab Mode in Section 6.

Permitted collection must remain proportionate to the approved objective. Jane must not interpret a successful HTTP response as permission to continue with additional paths, methods, downloads, authentication, or probing.

## 5. Prohibited Activities

Unless a separate written authorization expressly permits a narrowly defined laboratory activity, Jane must not be used to:

- Authenticate, log in, register accounts, or use credentials obtained from any source.
- Guess passwords, brute-force accounts, enumerate authentication controls, or bypass CAPTCHA, access controls, paywalls, or technical restrictions.
- Exploit vulnerabilities, conduct intrusive scanning, attempt command execution, alter content, or disrupt availability.
- Submit forms, upload files, send messages, create accounts, or contact suspected actors.
- Conduct transactions, purchase goods or services, operate escrow, or transfer cryptocurrency.
- Download, execute, render, unpack, or distribute malware, binaries, archives, or other potentially dangerous files.
- Intentionally seek, store, reproduce, or disseminate unlawful or severely harmful content.
- Publish accusations, doxxing material, personal details, harassment, threats, or identifying information about suspected individuals.
- Present a model output, similarity score, IP candidate, stylometric result, or graph relationship as proof of guilt or conclusive identity.
- Use Jane to evade lawful oversight, conceal unauthorized activity, or expand beyond an approved investigation scope.

### Sensitive Paths

Jane must not automatically request or probe sensitive paths on real targets, including:

```text
/.git/HEAD
/.env
/server-status?auto
/phpinfo.php
```

These paths may expose configuration, credentials, internal status, diagnostic information, or other sensitive data. They may be used only in a separately authorized laboratory environment with written permission, explicit allowlisting, defined timing, and logging. If a sensitive path is encountered unintentionally, the operator must stop further access and follow Section 10.

## 6. Authorized Lab Mode

Authorized Lab Mode is a separate operating mode for targets owned by the institution/operator or covered by explicit written authorization from the system owner.

Before activation, the authorization record must specify:

- Target identifiers and allowlisted domains, IPs, services, or laboratory hosts.
- The permitted methods, paths, request types, and data categories.
- The purpose, start and end time, and geographic or network boundaries where relevant.
- The named operator, supervising person, and institutional owner.
- Maximum request rate, concurrency, depth, page count, response size, and timeout.
- Prohibited actions and an immediate stop procedure.
- Log retention, evidence handling, disclosure restrictions, and reporting contacts.

Required controls:

- Default-deny allowlisting; no wildcard scope.
- Visible warning banner on every Authorized Lab Mode screen.
- A unique authorization reference attached to the investigation.
- Immutable audit logging of operator, time, target, method, result, and stop events.
- Automatic expiration at the end of the approved time window.
- No activation based solely on a user’s assertion of permission where institutional verification is required.

Example banner:

> **AUTHORIZED LAB MODE — RESTRICTED SCOPE**  
> Activity is permitted only for the written authorization record shown in this investigation. Stop immediately if the target, method, time window, or data type is outside scope.

## 7. Attribution, Confidence, and Human Review

Jane’s results are **leads, not conclusive identity findings, criminal findings, or legal conclusions**.

Every material analytical claim should, where available, retain:

- Investigation ID and batch ID.
- Source URL and capture timestamp.
- Evidence quote or exact source excerpt.
- Content hash and evidence location/offset.
- Extraction method and confidence level.
- Corroboration references and analyst review status.
- A clear distinction between source evidence, machine extraction, statistical inference, and analyst interpretation.

The following are corroborative signals and must not be treated as standalone proof:

- Stylometric similarity and Burrows’ Delta.
- Favicon hashes and template similarity.
- Server banners, ETags, and infrastructure relationships.
- Shared IOCs, wallet strings, handles, or email addresses.
- IP geolocation, hosting information, and ASN data.
- Co-occurrence, marketplace role labels, graph centrality, or community detection.
- Search-engine indexing, mirrored content, and repeated aliases.

High-confidence attribution should require multiple independent evidence types, meaningful source quality assessment, and documented human review. The number of signals alone does not establish independence: several observations derived from the same page, mirror, or copied dataset may represent one underlying source.

Preferred wording includes:

- “Candidate attribution”
- “Origin-IP candidate”
- “Observed co-occurrence”
- “Infrastructure similarity”
- “Stylometric similarity requiring corroboration”
- “Reported by the source; not independently verified”
- “Requires corroboration”

Avoid wording such as “identified criminal,” “proven operator,” or “confirmed guilty” unless an authorized legal process independently establishes the relevant conclusion.

## 8. Sensitive Content and Data Handling

### 8.1 Safety Filtering

Safety filtering must occur before content is stored, rendered in the dashboard, supplied to LLM analysis, or included in exports. Jane should use a deny-by-default approach for active content and potentially dangerous file types.

Safe defaults:

- Do not automatically download images, videos, binaries, executables, archives, or office documents.
- Do not execute or unpack downloaded content.
- Do not render active scripts, inline event handlers, or active hyperlinks.
- Prefer text-only, defanged, size-limited representations.
- Quarantine uncertain content rather than attempting to inspect it repeatedly.

### 8.2 Quarantine Procedure

If prohibited, highly sensitive, or dangerous content is encountered:

1. Stop the current job and prevent automatic retries.
2. Do not revisit, download, open, execute, share, or redistribute the content.
3. Preserve only the minimum necessary metadata and operational logs, such as investigation ID, source identifier, timestamp, request outcome, and reason for quarantine.
4. Record the event without copying unnecessary unlawful or sensitive material.
5. Notify the designated faculty, institutional security, or compliance authority.
6. Resume only after documented authorization and risk review.

### 8.3 Privacy and Storage Controls

- Apply data minimization and purpose limitation.
- Restrict database, workspace, export, and log access using least privilege.
- Mask personal identifiers by default in the UI and reports.
- Set retention periods before live collection begins; delete or securely destroy data when the approved period expires, subject to preservation obligations.
- Do not commit live raw captures, personal data, credentials, or sensitive indicators to public GitHub repositories.
- Do not place live raw captures in public cloud storage or upload them to third-party LLMs without documented institutional approval and a data-protection assessment.
- Separate research fixtures and synthetic demonstrations from live investigative data.
- Protect encryption keys, API credentials, and access logs; never embed secrets in source code or exports.

## 9. Evidence Integrity and Exports

Jane should preserve an evidence record containing, where applicable:

- Investigation ID and batch ID.
- Source URL and collection timestamp.
- HTTP status and permitted metadata.
- Content hash, preferably SHA-256.
- Evidence quote, character offsets, or source location.
- Extraction method, confidence, and validation state.
- Operator, job, and pipeline audit trail.
- Export creation time and export-file hash.

Operational requirements:

- Raw captures should be immutable after ingestion. Corrections should create a new version or annotation rather than silently rewriting the original.
- Analyst annotations, hypotheses, and labels must be distinguishable from source evidence and machine-extracted fields.
- Hashes support integrity checking; a hash alone does not prove authenticity, ownership, authorship, or legal admissibility.
- Reports must disclose collection limitations, missing data, uncertainty, and whether a finding is observed, inferred, or unverified.
- Every exported report should include:

> **Academic Prototype — Analyst Review Required**

Jane must not describe an automatically generated PDF as automatically “court-admissible.” Admissibility depends on the applicable forum, law, evidentiary foundation, provenance, collection method, authentication, and human testimony or explanation where required.

## 10. Incident Escalation

Stop collection immediately when any of the following occurs:

- Suspected access-control bypass or other prohibited activity.
- Encountered malware, dangerous files, child sexual abuse material, or other severely sensitive content.
- Evidence of compromise, exploitation, or a serious cyber incident.
- Collection outside the approved target, method, time window, or data scope.
- Unexpected interaction, form submission, authentication prompt, or actor contact.
- Loss of isolation, unexpected network connectivity, or a technical safeguard failure.

After stopping:

1. Preserve minimal metadata and relevant operational logs without unnecessarily copying sensitive content.
2. Record the investigation ID, time, system state, and reason for stopping.
3. Notify the designated faculty supervisor and institutional security/compliance contact.
4. Do not independently contact suspected actors, hosting providers, police, media, or external agencies.
5. Allow institutional and legal personnel to determine whether formal reporting, preservation, notification, or cooperation is required.
6. Do not resume until scope, safeguards, and authorization have been reviewed and documented.

## 11. Technical Safeguards

Jane should ship with the following conservative defaults:

```ini
SAFE_MODE=true
PASSIVE_OSINT_MODE=true
ACTIVE_PROBING=false
AUTHORIZED_LAB_MODE=false
ALLOW_FORM_SUBMISSION=false
ALLOW_AUTHENTICATION=false
ALLOW_ACTOR_CONTACT=false
ALLOW_CRYPTO_TRANSACTIONS=false
DOWNLOAD_BINARIES=false
DOWNLOAD_ARCHIVES=false
MAX_DEPTH=1
MAX_PAGES_PER_ONION=5
REQUIRE_EVIDENCE_QUOTES=true
ENABLE_EXPORT_AUDIT_LOG=true
```

Recommended additional controls:

```ini
MAX_RESPONSE_BYTES=1048576
MAX_REQUESTS_PER_MINUTE=6
MAX_CONCURRENT_REQUESTS=1
FOLLOW_REDIRECTS=false
EXECUTE_SCRIPTS=false
RENDER_ACTIVE_CONTENT=false
ALLOWLIST_REQUIRED_FOR_LAB_MODE=true
AUTO_RETRY_ON_SENSITIVE_CONTENT=false
MASK_PERSONAL_DATA_BY_DEFAULT=true
EXPORT_REQUIRES_AUDIT_RECORD=true
```

These settings are recommended safeguards, not a guarantee of legal compliance or technical isolation. They must be tested against the actual implementation and deployment environment.

## 12. Operator Acknowledgement

Before dispatching a live investigation, the operator must affirm all of the following:

```text
[ ] I have institutional approval and understand the permitted scope.
[ ] I will use Jane only for authorized, passive, defensive, read-only activity.
[ ] I will not bypass authentication, access controls, CAPTCHAs, or technical restrictions.
[ ] I will not contact actors, transact, submit forms, or download dangerous content.
[ ] I understand that Jane produces leads requiring human review, not proof of identity or guilt.
[ ] I will stop and escalate if prohibited content, a scope violation, or a security incident occurs.
[ ] I will protect personal data, evidence, credentials, and investigation exports.
[ ] I understand that Tor, Whonix, student status, SIH participation, and the NTRO context do not independently grant authorization.
```

**Dispatch rule:** A live investigation must not be dispatched unless the required acknowledgement is accepted and the investigation is within the institutionally approved scope.

## 13. Footer Summary

> **Jane is an academic defensive-intelligence prototype. Use only with authorization, within scope, and in passive read-only mode. Its outputs are evidence-linked investigative leads requiring human review—not proof of identity, guilt, or legal responsibility.**

---

This policy is operational guidance, not legal advice. Obtain written institutional approval and legal guidance before live deployment.
