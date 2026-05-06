# Threat Intelligence Platform — Feature & Functionality Survey

> Candidate #152 · Researched: 2026-05-03

## Solutions Analysed

| Tool | Type | Licence / Model | URL |
|------|------|-----------------|-----|
| ThreatConnect | Commercial SaaS | Enterprise subscription | https://threatconnect.com |
| Anomali ThreatStream | Commercial SaaS | Tiered enterprise pricing | https://www.anomali.com |
| Recorded Future | Commercial SaaS | Enterprise subscription ($25K–$250K/yr) | https://www.recordedfuture.com |
| Mandiant Advantage | Commercial SaaS | Enterprise subscription | https://www.mandiant.com |
| MISP | Open Source | AGPL / Community | https://www.misp-project.org |
| OpenCTI | Open Source | Apache 2.0 | https://filigran.io |
| SEKOIA.IO | Commercial SaaS | Subscription (~€2,000/month) | https://sekoia.io |
| EclecticIQ | Commercial SaaS | Enterprise subscription | https://www.eclecticiq.com |
| Flare | Commercial SaaS | Subscription (~$8,000/yr) | https://flare.io |
| Intel 471 | Commercial SaaS | Enterprise subscription | https://intel471.com |

## Feature Analysis by Solution

### ThreatConnect

**Core features**
- AI-curated threat intelligence prioritization based on business context
- Detection engineering with MITRE ATT&CK-driven rule mapping
- Automated alert triage and false-positive reduction
- Incident response playbook orchestration across SIEM/SOAR platforms
- Vulnerability prioritization tied to active adversary campaigns
- Threat hunting workflows with business-specific threat models

**Differentiating features**
- Financial risk mapping: ties threat impact to dollar value
- Analyst network: field analyst enrichment and feedback loops
- Polarity overlay: instant threat context in existing SOC workflows
- Deep integration feedback: detection engineering insights inform intelligence collection

**UX patterns**
- Analyst-centric orchestration: reduces manual effort through orchestration of response across tools
- Risk quantification: financial impact visualization for executive reporting
- Progressive relevancy: AI filters noise based on organizational threat model

**Integration points**
- SIEM platforms (Splunk, ELK, QRadar) for indicator/TTP push
- SOAR platforms for playbook triggering
- EDR/XDR systems for proactive blocking
- Vulnerability management tools for threat correlation
- Ticketing systems (Jira, ServiceNow) for auto-enrichment

**Known gaps**
- Primarily enterprise-focused; limited SMB/mid-market offerings
- Requires ongoing fine-tuning of business-context rules
- High cost barrier

**Licence / IP notes**
- Proprietary commercial software; no licensing concerns identified

---

### Anomali ThreatStream

**Core features**
- Feed aggregation from hundreds of commercial and open-source intelligence sources
- Automated data normalization and deduplication
- Confidence scoring and context tagging
- AI-powered enrichment (launched June 2025 with AI tiers)
- Agentic AI integration for automated analysis
- Threat prioritization across alerts and investigations

**Differentiating features**
- Wide feed ecosystem: largest aggregated source count in industry
- AI enrichment tiers: tiered AI capabilities for different use cases
- Agentic SOC integration: native AI agent orchestration

**UX patterns**
- Feed-centric workflow: emphasis on source aggregation and normalization
- Confidence-driven triage: analysts prioritize high-confidence indicators
- Progressive AI assistance: from basic enrichment to full agentic orchestration

**Integration points**
- 100+ threat intelligence feeds (commercial and open)
- Native API for SIEM/SOAR integration
- Agentic AI platform for automated analysis workflows
- Custom feed integration via REST API

**Known gaps**
- UI complexity noted in user feedback
- Expensive premium feeds
- Steeper learning curve vs. purpose-built SOC platforms

**Licence / IP notes**
- Proprietary commercial software; no licensing concerns identified

---

### Recorded Future

**Core features**
- ML-driven threat intelligence with broad source collection (dark web, open web)
- Natural language processing for unstructured threat report analysis
- Threat actor attribution and relationship mapping
- Phishing and malware campaign tracking
- Executive risk reporting with trend analysis
- Real-world intelligence from front-line incident response

**Differentiating features**
- Breadth of collection: dark web + open web + proprietary sources
- Strong NLP capabilities: extract insights from unstructured text
- Historical data depth: track threat actor evolution over time
- Analyst sourcing: leverage Mandiant's incident response expertise

**UX patterns**
- Executive-focused reporting: risk trending and strategic insights
- Deep investigation workflows: multi-year threat actor history
- Attribution-centric: emphasize actor relationships and campaigns

**Integration points**
- REST API for custom integrations
- Native SIEM connectors
- Alert integration for Splunk, ELK
- Threat actor timeline feeds (TAXII)

**Known gaps**
- Very high cost (~$25K–$250K/yr); overkill for many organizations
- Requires significant analyst expertise to leverage fully
- Long implementation timelines

**Licence / IP notes**
- Proprietary; owned by Mastercard (acquired 2024); no licensing concerns

---

### Mandiant Advantage

**Core features**
- Threat intelligence from front-line incident response
- High-fidelity attribution and campaign tracking
- Google Cloud integration for telemetry fusion
- Incident response playbook correlation
- Threat hunting enriched by IR experience
- Geopolitical threat context

**Differentiating features**
- IR-driven intelligence: real incident data informs threat models
- Google Cloud native: deep integration with GCP security services
- High-fidelity attribution: evidence-based actor assessment
- Frontline visibility: early-warning indicators from incident response work

**UX patterns**
- Incident-response workflow: map threats to real-world attacks
- Google Cloud-centric: tight integration with cloud security stack
- Strategic briefings: executive-level threat context

**Integration points**
- Google Cloud Security Command Center
- Workspace threat detection
- Chronicle SIEM integration
- Custom API integrations

**Known gaps**
- Google Cloud lock-in; limited multi-cloud support
- Enterprise-only pricing model
- Requires GCP deployment

**Licence / IP notes**
- Proprietary; Google-owned; no licensing concerns

---

### MISP

**Core features**
- Centralized IOC storage and management in structured format
- Automatic export to IDS/SIEM systems (STIX, OpenIOC, YARA, Sigma)
- Multi-instance synchronization for distributed intelligence sharing
- Taxonomy-based metadata tagging (TLP, estimative language, GDPR)
- Visualization and correlation dashboards
- PyMISP Python API for programmatic access

**Differentiating features**
- Completely open source and self-hosted
- Modular plugin architecture (MISP Modules for extensibility)
- Community-driven development with global user communities
- No licensing restrictions on data or usage
- Multi-site federation for large organizations

**UX patterns**
- Community-centric: collaborative threat sharing across organizations
- Standards-based: STIX/TAXII open formats throughout
- Progressive disclosure: taxonomy tagging reveals complexity when needed
- Self-service: full control over data and infrastructure

**Integration points**
- STIX/TAXII feeds (both consuming and publishing)
- YARA rule export for IDS
- Sigma rule export for SIEM
- REST API via PyMISP
- Custom module development with Python

**Known gaps**
- Dated UI/UX (acknowledged by maintainers)
- High operational overhead for self-hosting
- Limited built-in enrichment vs. commercial platforms
- Requires skilled staff for deployment and tuning
- No native dark web monitoring

**Licence / IP notes**
- AGPL 3.0 (GNU Affero General Public License): requires sharing modifications
- Community support primarily; commercial support available via CIRCL
- **Important:** AGPL requires any modifications to be shared back to community

---

### OpenCTI

**Core features**
- Graph-based threat intelligence organization (knowledge graph)
- Confidence scoring and relationship inference
- 230+ pre-built security tool integrations (one-click deployment)
- Rapid threat enrichment (seconds vs. hours)
- Visual MITRE ATT&CK Navigator integration
- Role-based collaborative workspaces

**Differentiating features**
- Graph-native architecture: intelligence relationships as first-class objects
- One-click integrations: 230+ pre-configured connectors
- Relationship inference: automated pattern detection across entities
- Speed: 70% faster threat assessment vs. traditional TIPs
- Modern UX: 4.6/5 G2 ratings, Gartner 5/5 review

**UX patterns**
- Knowledge graph visualization: understand threat relationships visually
- Rapid assessment: enrichment in seconds enables fast triage
- Collaborative investigation: role-based workspaces for teams
- Open integration model: reduce analyst context switching

**Integration points**
- 230+ native integrations (SIEM, SOAR, EDR, ticketing, etc.)
- REST API for custom development
- Graph query language for advanced analysis
- STIX 2.1 import/export
- Custom object definitions for domain-specific intelligence

**Known gaps**
- Resource-intensive deployment (compared to lightweight SaaS)
- Steeper learning curve for graph-based concepts
- Community support primarily (commercial support via Filigran)

**Licence / IP notes**
- Apache 2.0 (permissive open source)
- Commercial support available via Filigran
- No licensing restrictions on modifications or deployment
- Safe for proprietary derivative use

---

### SEKOIA.IO

**Core features**
- Cloud-native European TIP with EU data residency
- Analyst workflow optimization
- Detection rule management and deployment
- Threat hunting capabilities
- Modern web-based interface
- STIX 2.1 data normalization

**Differentiating features**
- EU-focused: guarantees data residency in EU
- Regulatory compliance: built for GDPR and EU-specific requirements
- Modern UX: newer than MISP/OpenCTI, cleaner interface
- Regional pricing: more affordable than U.S.-centric competitors

**UX patterns**
- Compliance-first: privacy and regulatory controls prominent
- Analyst-centric: workflow optimization for threat teams
- Progressive feature set: starting from SMB-appropriate features

**Integration points**
- REST API for SIEM/SOAR integration
- STIX feeds
- Detection rule export
- Custom integrations via API

**Known gaps**
- Smaller feed ecosystem vs. U.S. competitors
- Less market visibility than leaders
- Limited dark web coverage compared to Recorded Future/Intel 471

**Licence / IP notes**
- Proprietary commercial software; no licensing concerns

---

### EclecticIQ

**Core features**
- Six-stage intelligence lifecycle support (Direction, Collection, Processing, Analysis, Actioning, Dissemination)
- AI-powered entity extraction and automated deduplication
- MITRE ATT&CK Navigator integration
- Observable Risk Score for threat prioritization
- Malware sandbox integration
- Finished intelligence report generation with templates
- REST API for partner ecosystem integration

**Differentiating features**
- Lifecycle-focused: explicit support for all intelligence production stages
- DISARM Framework integration: disinformation/propaganda analysis
- Analyst-centric collaboration: workspaces for team coordination
- Custom object support: extend STIX for specialized threats
- AI-driven entity extraction: reduce manual normalization work

**UX patterns**
- Structured intelligence production: guides analysts through proven workflows
- Progressive automation: AI assists at key decision points
- Collaborative investigation: role-based workspaces and shared analysis

**Integration points**
- STIX 2.1 and EIQ-JSON formats
- REST API for custom integrations
- MITRE ATT&CK Navigator data
- Malware sandbox APIs
- Elasticsearch integration for search

**Known gaps**
- Niche market positioning vs. broader market leaders
- Less brand recognition in U.S. market
- Enterprise-focused (limited SMB support)

**Licence / IP notes**
- Proprietary commercial software; no licensing concerns

---

### Flare

**Core features**
- Continuous dark web and clear web monitoring
- Exposed credential detection (breached identity tracking)
- Ransomware blog monitoring and threat actor profile tracking
- Stealer log detection and analysis
- Native SIEM/SOAR integration for automated remediation
- Identity Exposure Management (Entra ID integration)
- Risk scoring and prioritization

**Differentiating features**
- Threat exposure management (TEM) focus: combines TIP with attack surface
- Dark web specialization: exclusive forum access and criminal marketplace data
- Rapid deployment: setup in <30 minutes
- Automated remediation: direct integration with identity platforms
- Weekly breach identity updates: high-velocity threat data

**UX patterns**
- Rapid onboarding: minimal configuration for quick deployment
- Risk-driven triage: exposure prioritization by organizational context
- Workflow integration: remediation actions flow through existing tools

**Integration points**
- SIEM platforms (Splunk, ELK, etc.)
- SOAR platforms (Palo Alto, Splunk)
- Identity platforms (Azure Entra ID)
- Ticketing systems (Jira, ServiceNow)
- Custom webhooks for automation

**Known gaps**
- Narrower scope than full TIPs (TEM-focused vs. comprehensive intelligence)
- Less emphasis on TTPs and campaign tracking
- Limited MITRE ATT&CK integration
- Smaller feed ecosystem

**Licence / IP notes**
- Proprietary commercial software; no licensing concerns

---

### Intel 471

**Core features**
- Cyber Human Intelligence (HUMINT): analyst-enriched threat data
- Three-portfolio platform (Verity471): Exposure, Intelligence, Hunting
- Attack surface management with threat intelligence prioritization
- Behavioral-based threat hunting with pre-validated content
- Adversary and marketplace monitoring (underground forum access)
- Threat actor tactical/tool/infrastructure attribution

**Differentiating features**
- HUMINT advantage: human intelligence analysts + automated collection
- Underground marketplace access: direct visibility into criminal marketplaces
- Pre-attack planning visibility: detect threat actor preparation
- Behavioral hunting: validated hunting signatures
- Actor specialization: deep dossiers on sophisticated threat actors

**UX patterns**
- Actor-centric intelligence: organize around adversary entities
- Marketplace transparency: visibility into criminal infrastructure
- Hunting readiness: pre-validated behavioral content for rapid hunting

**Integration points**
- REST API for SIEM/SOAR integration
- Threat actor feed APIs
- Custom hunt rule export
- Verity471 platform ecosystem

**Known gaps**
- Very specialized focus (deep underground marketplace access)
- Highest price point
- Not suitable for organizations with narrow scope
- Less emphasis on vulnerability/exposure management

**Licence / IP notes**
- Proprietary commercial software; no licensing concerns

---

## Cross-Cutting Feature Themes

### Table-Stakes Features

Every threat intelligence platform in this space must include:

- **IOC ingestion and normalization** — Support for STIX 2.1, TAXII, OpenIOC, and raw indicator formats with automatic deduplication
- **Multi-source feed aggregation** — Ability to ingest from commercial feeds, open sources, and custom sources simultaneously
- **Search and filtering** — Full-text search, boolean operators, taxonomy-based filtering, and saved search persistence
- **Visualization and dashboards** — Indicator heatmaps, threat actor timelines, campaign tracking, threat geography
- **Role-based access control** — User management, permission levels, audit logging
- **RESTful API** — Programmatic access for automation, SIEM integration, and ecosystem tooling
- **MITRE ATT&CK mapping** — Correlate TTPs to attack framework; navigation tools expected
- **Alert and event management** — Ability to track related indicators as discrete events; link to incident context
- **Export capabilities** — Generate detection rules (YARA, Sigma), feeds (STIX/TAXII), and reports in standard formats

### Differentiating Features

Capabilities that set leaders apart:

- **AI-powered enrichment** — Automated false-positive reduction, IOC confidence scoring, missing-link inference (increasingly expected)
- **Dark web monitoring** — Threat actor forum access, ransomware blog tracking, criminal marketplace data
- **Automated playbook/response orchestration** — Trigger SIEM rules, SOAR playbooks, or EDR actions automatically based on indicator arrival
- **Business context and risk scoring** — Financial impact quantification, organizational threat model alignment, industry/tech-stack relevance
- **Unified incident response integration** — Link threat intelligence to active incidents; correlate TIP findings with EDR/SIEM alerts
- **Threat actor attribution** — Confidence-scored actor attribution, campaign tracking, geopolitical context
- **Analyst collaboration workflows** — Shared workspaces, finished intelligence production, peer review tools
- **Graph-based relationship inference** — Automatic detection of attacker relationships and campaign connections
- **Rapid enrichment and assessment** — Sub-second enrichment responses; real-time alert prioritization

### Underserved Areas / Opportunities

Genuine gaps where a new entrant could differentiate:

- **Conversational threat intelligence interface** — Natural language query: "Show me all TTPs used by Lazarus Group targeting financial institutions in the past 90 days" (minimal effort required)
- **Automated IOC extraction from unstructured reports** — Parse threat blog posts, security research, dark web posts; automatically extract and normalize indicators without analyst effort
- **Industry/technology-specific relevance filtering** — Filter global threat feeds to show only threats relevant to an organization's specific stack (e.g., "threats targeting Kubernetes + AWS + Node.js")
- **Self-serve threat intelligence for SMBs** — Open-source or low-cost option with modern UX and minimal operational overhead (current options require significant expertise)
- **Continuous detection rule generation** — Auto-generate Sigma/YARA rules from ingested threat reports; reduce latency from threat discovery to defensive deployment
- **Lightweight standalone IOC management** — For organizations that don't need SOAR/orchestration; lightweight tool with excellent UX and feed management
- **Supplier/third-party risk correlation** — Link threat intel to vendor/supply-chain risk; correlate with third-party security posture data
- **Hybrid open-source + cloud** — Open-source core with optional cloud enrichment services; reduce lock-in concerns

### AI-Augmentation Candidates

Features currently implemented via manual work or rule-based systems where AI could excel:

- **Automated IOC extraction** — Current: manual analyst parsing of threat reports. Better: LLM-based extraction with confidence scoring; dramatically reduce analyst effort
- **Campaign and actor attribution** — Current: analyst-driven pattern matching across sparse data points. Better: graph-based ML reasoning infer relationships; surface hidden campaign connections
- **False-positive reduction** — Current: rules-based confidence scoring. Better: ML models learn from analyst feedback; adapt to organization's false-positive patterns
- **Threat relevance scoring** — Current: rule-based filtering (if threat targets your industry + your technology). Better: ML learns from incident history; predict which threats are likely to affect your organization
- **Detection rule generation** — Current: analysts write Sigma/YARA manually from threat reports. Better: LLMs auto-generate rules with minimal human review
- **Finished intelligence generation** — Current: analysts write reports manually. Better: LLM summarize threat data, generate executive briefs, auto-populate TTP tables
- **Indicator quality assessment** — Current: static confidence scores. Better: ML assess indicator quality based on source history, historical accuracy, threat actor sophistication
- **Context-aware alert triage** — Current: SIEM rules fire independently. Better: ML correlate alerts with threat landscape; suppress false positives based on real threat activity

---

## Legal & IP Summary

**MISP considerations:** MISP is licensed under AGPL 3.0, which requires any modifications to be shared back to the community. Organizations cannot use MISP as a base for proprietary derivatives without complying with AGPL's copyleft provisions. This is acceptable for open-source projects but may constrain commercial deployments. OpenCTI, by contrast, uses permissive Apache 2.0 licensing, allowing unrestricted commercial use and modification.

**Patent concerns:** No known software patents were identified on core TIP functionality (IOC management, feed aggregation, STIX/TAXII). However, specific AI enrichment techniques and attribution methodologies may be patent-encumbered; independent legal review is recommended before implementing proprietary ML-based enrichment algorithms. Financial risk-mapping methodologies (ThreatConnect's approach) may also be patented; review prior to adoption.

**Dark web sourcing:** Intel 471, Flare, and Recorded Future rely on dark web and underground forum access to differentiate. Organizations implementing similar capabilities should conduct independent legal review of data sourcing practices, as forum access terms and data sharing legality may vary by jurisdiction.

**No material was omitted due to copyright uncertainty.** All sources were publicly available product documentation, open-source repositories, or published research.

---

## Recommended Feature Scope

Based on the analysis above, here's a prioritised feature scope for the project:

### Must-Have (MVP)

- **STIX 2.1 data model and import/export** — Foundation for all integrations; users expect standard format support
- **Multi-source feed ingestion** — Ingest from 10+ free/commercial feeds with automatic deduplication and normalization
- **IOC search, filter, and correlation** — Full-text search, taxonomy-based filtering (TLP, estimative language), correlation of related indicators
- **RESTful API** — Enable SIEM/SOAR integration from day one; programmatic access for automation
- **MITRE ATT&CK mapping** — Tag indicators with TTP; include navigator for visualization
- **Role-based access and audit logging** — Multi-user support with permission levels; track who accessed what and when
- **Automated threat indicator export** — Generate YARA rules for IDS, Sigma for SIEM with one click

### Should-Have (v1.1)

- **AI-powered IOC confidence scoring** — Reduce false positives by learning from analyst feedback; improve over time
- **Incident correlation workflow** — Link related indicators; correlate with external incident data (if available)
- **Dark web feed integration** — Add 2–3 dark web sources (e.g., ransomware blog tracking, threat actor forum aggregates)
- **Analyst collaboration spaces** — Shared workspaces for team investigation; draft and peer-review finished intelligence
- **Rapid enrichment API** — Sub-second indicator lookup; enable real-time SOC integration
- **Threat actor timeline visualization** — Track actor evolution, campaigns, infrastructure changes over time
- **Business context tagging** — Allow users to mark threats as "relevant to our org" based on industry, technology, geography

### Nice-to-Have (Backlog)

- **Conversational query interface** — Natural language threat questions ("threats targeting our tech stack"); powered by LLM
- **Automated IOC extraction** — Parse threat blog posts and reports; auto-extract and normalize indicators
- **Supply chain risk correlation** — Link threat intel to vendor/supplier risk data
- **Threat hunting playbooks** — Pre-built behavioral hunting templates; guided workflow for threat hunts
- **Graph-based relationship inference** — Automatic detection of campaign/actor relationships; surface hidden connections
- **AI-generated detection rules** — Auto-generate rules from threat reports; minimize analyst effort
- **Mobile application** — On-the-go threat monitoring and alert response
