# Standards & API Reference

> Project: Threat Intelligence Platform · Generated: 2026-05-03

## Industry Standards & Specifications

### ISO Standards

- **ISO/IEC 27001:2022** — Information security management systems; Annex A control A.5.7 (Threat intelligence) explicitly requires organisations to collect and analyse information about threats to produce threat intelligence. URL: https://www.iso.org/standard/82875.html

- **ISO/IEC 27002:2022** — Implementation guidance for ISO 27001 controls; Control 5.7 details how threat intelligence should be collected from internal and external sources, analysed, and used to inform security controls. URL: https://www.iso.org/standard/75652.html

- **ISO/IEC 27035:2023 — Information Security Incident Management** — Governs the integration of threat intelligence into incident detection and response workflows; threat indicators feed into the event detection stage of the incident management lifecycle. URL: https://www.iso.org/standard/74169.html

### W3C & IETF Standards

- **RFC 9110 — HTTP Semantics** — Governs the REST API transport used by threat intelligence sharing endpoints (TAXII 2.1 endpoints are HTTP-based); relevant to API design of TIP management interfaces. URL: https://datatracker.ietf.org/doc/html/rfc9110

- **RFC 7519 — JSON Web Token (JWT)** — Used in TAXII 2.1 for bearer token authentication and in TIP REST API authentication flows. URL: https://datatracker.ietf.org/doc/html/rfc7519

- **RFC 6749 — OAuth 2.0 Authorization Framework** — Standard authorization protocol used by commercial TIPs (Recorded Future, Mandiant/Google Threat Intelligence) for API access control. URL: https://datatracker.ietf.org/doc/html/rfc6749

### Data Model & API Specifications

- **STIX 2.1 — Structured Threat Information eXpression** — OASIS standard (co-developed with MITRE) defining a JSON-based language for describing cyber threat intelligence including threat actors, campaigns, malware, attack patterns, indicators, vulnerabilities, and relationships. The ATT&CK dataset is distributed in STIX 2.1 format. URL: https://oasis-open.github.io/cti-documentation/stix/intro

- **TAXII 2.1 — Trusted Automated eXchange of Intelligence Information** — OASIS standard defining an HTTP-based protocol for exchanging STIX 2.1 objects via Collections and Channels; the de facto transport layer for automated threat intelligence sharing between ISACs, government agencies, and enterprise platforms. URL: https://oasis-open.github.io/cti-documentation/taxii/intro

- **MITRE ATT&CK** — Knowledge base of adversary tactics, techniques, and procedures (TTPs) structured as STIX 2.1 objects; the standard taxonomy for describing observed attacker behaviour; machine-readable data available at github.com/mitre-attack/attack-stix-data. URL: https://attack.mitre.org/

- **MITRE ATT&CK STIX Data** — The full ATT&CK dataset in STIX 2.0 and STIX 2.1 formats, consumable via the python-stix2 library or direct JSON import; used by all major TIPs for TTP enrichment. URL: https://github.com/mitre-attack/attack-stix-data

- **OpenAPI 3.1** — Used to describe the REST management APIs of commercial TIPs and TAXII 2.1 server implementations; enables SDK code generation and Terraform provider development. URL: https://spec.openapis.org/oas/latest.html

- **GraphQL** — OpenCTI's native API protocol, enabling flexible querying of the threat intelligence knowledge graph including filtering, pagination, and cross-entity relationship traversal. URL: https://graphql.org/

- **MISP Core Format** — Open standard JSON event format used by MISP instances; defines events, attributes, objects, tags, galaxies, and taxonomies for structured indicator sharing. URL: https://www.misp-project.org/misp-training/a.7-rest-API.pdf

### Security & Authentication Standards

- **NIST SP 800-150 — Guide to Cyber Threat Information Sharing (2016)** — Foundational NIST guidance for establishing threat intelligence sharing programmes; covers sharing goals, source identification, trust models, publication rules, and integration with security operations. URL: https://csrc.nist.gov/pubs/sp/800/150/final

- **NIST SP 800-61 Rev. 3 (Draft) — Computer Security Incident Handling Guide** — Integrates threat intelligence into incident response phases; recommends using CTI to prioritise incident severity and identify related attack campaigns. URL: https://csrc.nist.gov/publications/detail/sp/800-61/3/draft

- **NIST CSF 2.0 — Cybersecurity Framework** — The Identify (ID.RA: Risk Assessment) and Detect (DE.CM: Continuous Monitoring) functions explicitly reference threat intelligence as an input; TIPs operationalise these functions. URL: https://www.nist.gov/cyberframework

- **OWASP API Security Top 10** — Governs the design of TIP management APIs and TAXII endpoints; API2 (Broken Authentication) and API8 (Security Misconfiguration) are particularly relevant to TAXII server hardening. URL: https://owasp.org/API-Security/

- **Traffic Light Protocol (TLP 2.0)** — FIRST.org standard for controlling intelligence sharing; TLP:RED, TLP:AMBER, TLP:GREEN, TLP:CLEAR colours define distribution boundaries; used natively in MISP, OpenCTI, and TAXII-based sharing. URL: https://www.first.org/tlp/

- **GDPR Article 6 & Recital 49** — Recital 49 explicitly permits processing of personal data for network security and threat intelligence purposes; governs how TIPs handle indicators containing personal data (IP addresses, email addresses). URL: https://gdpr-info.eu/recitals/no-49/

- **EU NIS2 Directive — Article 23 & Annex** — Requires entities to participate in information sharing arrangements; encourages use of structured threat intelligence formats for incident reporting and sector-specific ISAC participation. URL: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022L2555

### MCP Server Specifications

Threat intelligence platforms are actively integrating with the Model Context Protocol (MCP) ecosystem to enable AI-agent-driven intelligence workflows:

- **OpenCTI MCP Server** — Official MCP server exposing OpenCTI's GraphQL API to AI agents; enables natural-language querying of threat actors, campaigns, indicators, and TTPs from the OpenCTI knowledge base. URL: https://mcpmarket.com/server/opencti-server

- **OpenCTI MCP Integration Guide** — Detailed guide on using the OpenCTI MCP Server as a bridge for AI agents to interact with the full OpenCTI threat intelligence platform. URL: https://skywork.ai/skypage/en/mastering-threat-intelligence-opencti-mcp/1981604181069369344

---

## Similar Products — Developer Documentation & APIs

### MISP (Open Source)

- **Description:** Open-source (AGPL-3.0) Malware Information Sharing Platform; the most widely-deployed open-source TIP with thousands of community instances globally; native STIX 2.1 and TAXII 2.1 support, taxonomies, galaxies, and a restSearch API.
- **API Documentation:** https://www.misp-project.org/documentation/ and https://www.circl.lu/doc/misp/automation/
- **OpenAPI Spec:** https://www.misp-project.org/openapi/
- **SDKs/Libraries:** PyMISP (Python, GitHub: MISP/PyMISP); MISP modules ecosystem (github.com/MISP/misp-modules)
- **Developer Guide:** https://www.misp-project.org/documentation/
- **Standards:** REST/JSON, XML, STIX 2.1, TAXII 2.1, OpenAPI
- **Authentication:** API key (auth key per user); optional mTLS for feed authentication

### OpenCTI (Open Source)

- **Description:** Open-source (Apache 2.0) next-generation Cyber Threat Intelligence platform by Filigran; uses a knowledge graph model with native STIX 2.1 data representation and a GraphQL API; connectors for MISP, MITRE ATT&CK, AlienVault OTX, VirusTotal, and 100+ sources.
- **API Documentation:** https://docs.opencti.io/latest/reference/api/
- **GraphQL Playground:** https://docs.opencti.io/latest/development/api-usage/
- **SDKs/Libraries:** pycti (Python SDK, PyPI); JavaScript/TypeScript client library
- **Developer Guide:** https://docs.opencti.io/latest/
- **Standards:** GraphQL, REST/JSON, STIX 2.1, TAXII 2.1
- **Authentication:** API token (per user); OAuth 2.0 / OIDC via identity providers (Okta, Keycloak, Azure AD)

### Recorded Future

- **Description:** Commercial threat intelligence platform with the Intelligence Graph indexing 1M+ sources (open web, dark web, technical feeds, Insikt Group research); provides risk scores, entity enrichment, and predictive intelligence via REST API.
- **API Documentation:** https://docs.recordedfuture.com/reference/get-started
- **API Portal:** https://api.recordedfuture.com/
- **SDKs/Libraries:** Elastic integration (ti_recordedfuture); SOAR connectors for Splunk SOAR, Palo Alto XSOAR, Microsoft Sentinel
- **Developer Guide:** https://docs.recordedfuture.com/
- **Standards:** REST/JSON, STIX 2.1 export, TLP 2.0
- **Authentication:** API key (X-RFToken header)

### Google Threat Intelligence (formerly Mandiant + VirusTotal)

- **Description:** Google Cloud's unified threat intelligence service combining Mandiant's frontline research (350+ tracked threat actors), VirusTotal's file/URL analysis, and Google's threat visibility; exposes both a REST API and integration with Google Security Operations (Chronicle).
- **API Documentation:** https://docs.cloud.google.com/threat-intelligence/reference/rest
- **SDKs/Libraries:** Google Cloud client libraries (Python, Go, Java, Node.js); VirusTotal Python SDK
- **Developer Guide:** https://docs.cloud.google.com/threatintelligence_prod
- **Standards:** REST/JSON, STIX 2.1 (Mandiant ThreatScape API v4), OpenAPI
- **Authentication:** Google Cloud service account (OAuth 2.0); API key for VirusTotal endpoints

### Anomali ThreatStream

- **Description:** Commercial TIP with a federated threat intelligence model; aggregates open-source, premium, and ISAC feeds; provides TAXII 2.1 server for downstream consumption and integrates with SIEM/SOAR platforms.
- **API Documentation:** https://ui.threatstream.com/api/v2/ (requires account)
- **SDKs/Libraries:** Cortex XSOAR integration (xsoar.pan.dev/docs/reference/integrations/anomali-threat-stream-v3); Elastic integration (ti_anomali)
- **Developer Guide:** Anomali developer portal (account required)
- **Standards:** REST/JSON, STIX 2.1, TAXII 2.1, OpenAPI
- **Authentication:** API key + username (HTTP Basic Auth over HTTPS)

### ThreatConnect

- **Description:** Threat intelligence operations platform combining TIP, SOAR, and threat modelling; strong playbook automation capabilities and native ATT&CK mapping; widely used in large enterprises and MSSPs.
- **API Documentation:** https://docs.threatconnect.com/en/latest/rest_api/rest_api.html
- **SDKs/Libraries:** tcex (Python SDK, PyPI); ThreatConnect Go SDK; JavaScript SDK
- **Developer Guide:** https://docs.threatconnect.com/
- **Standards:** REST/JSON, STIX 2.1, TAXII 2.1, OpenAPI
- **Authentication:** API key + access ID (HMAC-SHA256 request signing)

### EclecticIQ Platform

- **Description:** Enterprise TIP designed for intelligence-led security operations; provides a structured intelligence production workflow (collection → analysis → dissemination) with TAXII 2.1 server and STIX 2.1 native storage.
- **API Documentation:** https://developers.eclecticiq.com/
- **SDKs/Libraries:** Python SDK (eclecticiq-sdk); TAXII client libraries
- **Developer Guide:** https://developers.eclecticiq.com/
- **Standards:** REST/JSON, STIX 2.1, TAXII 2.1, OpenAPI 3.0
- **Authentication:** API token (Bearer); OAuth 2.0 for SSO

### VirusTotal (Google)

- **Description:** Online file, URL, domain, and IP reputation service processing 2M+ samples/day; API provides file/URL analysis, intelligence feeds, and threat actor infrastructure pivoting.
- **API Documentation:** https://developers.virustotal.com/reference/overview
- **SDKs/Libraries:** vt-py (Python, PyPI); vt-go (Go); VirusTotal CLI
- **Developer Guide:** https://developers.virustotal.com/
- **Standards:** REST/JSON, OpenAPI, STIX 2.1 export
- **Authentication:** API key (x-apikey header); Premium API for enterprise feeds

### AlienVault OTX (AT&T Cybersecurity)

- **Description:** Open threat exchange community platform with 200,000+ participants sharing indicators via Pulses (curated threat bundles); free REST API with STIX 2.1 and TAXII 2.1 support.
- **API Documentation:** https://otx.alienvault.com/api
- **SDKs/Libraries:** OTX Python SDK (PyPI: OTXv2); available in OpenCTI connector ecosystem
- **Developer Guide:** https://otx.alienvault.com/api
- **Standards:** REST/JSON, STIX 2.1, TAXII 2.1
- **Authentication:** API key (X-OTX-API-KEY header); free registration required

---

## Notes

- **STIX/TAXII 2.1 as the lingua franca**: STIX 2.1 + TAXII 2.1 are universally supported across all major TIPs (open and commercial), ISACs, and government sharing portals (US-CERT, ENISA, CIRCL). Any new TIP must implement these as table-stakes.

- **OpenCTI MCP integration (2025-2026)**: OpenCTI's official MCP server enables AI agents to query threat intelligence knowledge graphs via natural language, marking a significant shift toward AI-native threat intelligence workflows. This is the most mature MCP integration in the TIP space as of May 2026.

- **MITRE ATT&CK v16+ (2025)**: Continued expansion of ATT&CK coverage (ICS, mobile, cloud sub-techniques) means any TIP must maintain live ATT&CK synchronisation via the STIX 2.1 feed at github.com/mitre-attack/attack-stix-data.

- **Traffic Light Protocol 2.0**: TLP 2.0 (published by FIRST.org, 2022) replaced TLP 1.0 with a clearer four-colour scheme; all sharing communities now mandate TLP 2.0 compliance for published intelligence.

- **Open-source landscape**: MISP (AGPL-3.0) and OpenCTI (Apache 2.0) together cover most TIP use cases and have strong community ecosystems; commercial differentiation centres on threat actor attribution, dark web coverage, and managed intelligence feeds.
