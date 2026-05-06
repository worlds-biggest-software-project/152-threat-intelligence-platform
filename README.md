# Threat Intelligence Platform

> Part of the [worlds-biggest-software-project](https://github.com/worlds-biggest-software-project) initiative.
>
> An AI-native, open-source platform for ingesting, correlating, enriching, and operationalising cyber threat intelligence across an analyst's workflow.

The Threat Intelligence Platform (TIP) collects indicators of compromise (IOCs), threat actor data, and TTPs from commercial and open feeds, normalises them into STIX 2.1, and surfaces actionable intelligence to security analysts and SOC teams. It is built for mid-to-large enterprises, MSSPs, government CERTs, and ISACs that need a modern, standards-based alternative to expensive commercial suites and dated open-source tools.

---

## Why a new Threat Intelligence Platform?

- Commercial leaders such as Recorded Future (~$25K–$250K/yr), ThreatConnect, and Mandiant Advantage are priced for large enterprises, leaving SMBs and mid-market teams underserved.
- The most-deployed open-source TIP, MISP, has an acknowledged dated UI and high operational overhead, and its AGPL 3.0 licence constrains some commercial deployments.
- OpenCTI offers a modern graph-based UX under Apache 2.0 but is resource-intensive and has a steep learning curve around graph concepts.
- AI capabilities in incumbents are tiered behind premium pricing (e.g. Anomali's June 2025 AI tiers), and most platforms still rely on manual analyst parsing of unstructured threat reports.
- Mandiant Advantage and similar offerings introduce cloud lock-in (Google Cloud), limiting deployment flexibility for multi-cloud or sovereign environments.

---

## Key Features

### IOC Ingestion and Standards Support

- STIX 2.1 data model with import/export
- Multi-source feed ingestion across commercial, open-source, and custom sources with automatic deduplication and normalisation
- TAXII 2.1 transport for sharing intelligence between servers and clients
- OpenIOC support for legacy integrations
- Taxonomy-based metadata tagging including TLP, estimative language, and GDPR markers

### Analyst Workflow and Collaboration

- IOC search, filter, and correlation with full-text search and boolean operators
- Role-based access control with audit logging
- Analyst collaboration workspaces for shared investigation and peer-reviewed finished intelligence
- Threat actor timeline visualisation tracking actor evolution, campaigns, and infrastructure changes
- Business context tagging by industry, technology stack, and geography

### Detection and Response Integration

- MITRE ATT&CK mapping with navigator visualisation
- Automated detection rule export for YARA, Sigma, and Snort
- Rapid enrichment API for sub-second indicator lookup from SOC tooling
- RESTful API for SIEM, SOAR, EDR, and ticketing integrations

### AI-Augmented Intelligence

- AI-powered IOC confidence scoring that learns from analyst feedback
- Automated IOC extraction from unstructured threat reports, blogs, and dark web posts
- Conversational natural-language query interface over the intel corpus
- Graph-based relationship inference for campaign and actor attribution
- AI-generated detection rules derived from ingested threat reports

### External Threat Coverage

- Dark web feed integration including ransomware blog tracking and threat actor forum aggregates
- Incident correlation workflow linking related indicators to external incident data

---

## AI-Native Advantage

Incumbent TIPs depend heavily on analyst effort to parse unstructured reports, score indicator confidence, and write detection rules. This project uses LLMs to extract and normalise IOCs from blogs, research, and dark web sources without analyst intervention, applies graph-based reasoning to infer campaign attribution from sparse data, and auto-generates Sigma, YARA, and Snort rules from ingested intelligence. A natural-language analyst interface lets teams query the corpus conversationally (for example, "Show me all TTPs used by Lazarus Group targeting financial institutions in the past 90 days"), and proactive relevance scoring filters global feed noise to surface only intelligence relevant to a given technology stack and industry.

---

## Tech Stack & Deployment

The platform is designed around STIX 2.1 as the core data model and TAXII 2.1 as the sharing transport, with MITRE ATT&CK as the common enrichment vocabulary. A RESTful API enables SIEM/SOAR integration from day one. Deployment targets include self-hosted installations (mirroring MISP and OpenCTI patterns) and cloud-native operation, with a hybrid mode pairing an open-source core with optional cloud enrichment services to reduce lock-in concerns. SDK and integration patterns follow the established TIP ecosystem of Python APIs, native SIEM connectors, and webhook-based automation.

---

## Market Context

The global cyber threat intelligence market was valued at approximately USD 7–9 billion in 2025 and is projected to exceed USD 18 billion by 2030 at a CAGR of around 15% (research.md). Commercial platforms range from roughly $25K/year for SMB-oriented offerings to $500K+/year for large SOC teams; recent transactions include Mastercard's ~$2.65 billion acquisition of Recorded Future (2024) and Dataminr's announced $290 million acquisition of ThreatConnect (October 2025). Primary buyers are SOC managers and threat analysts at mid-to-large enterprises, government CERTs and ISACs, MSSPs building shared intelligence services, and financial-sector threat teams under regulatory pressure.

---

## Project Status

> This project is in the **research and specification phase**.  
> Contributions, feedback, and domain expertise are welcome.

---

## Contributing

We welcome contributions from developers, domain experts, and potential users.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Important:** All contributions must be your own original work or clearly attributed
open-source material with a compatible licence. Copyright infringement and licence
violations will not be tolerated and will result in immediate removal of the offending
contribution. If you are unsure whether a piece of code, text, or other material is
safe to contribute, open an issue and ask before submitting.

---

## Licence

Licence to be determined. See [discussion](#) for context.
