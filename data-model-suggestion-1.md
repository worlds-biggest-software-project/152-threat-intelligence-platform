# Data Model Suggestion 1: Entity-Centric Normalized Relational

> Project: Threat Intelligence Platform · Created: 2026-05-19

## Philosophy

This approach creates a dedicated PostgreSQL table for each STIX 2.1 Domain Object (SDO), Cyber Observable (SCO), and Relationship Object (SRO) type. The schema mirrors the STIX specification almost directly: every STIX object type maps to a table, every required property maps to a column, and every relationship maps to a foreign key or junction table. Reference data (MITRE ATT&CK techniques, TLP markings, kill chain phases) lives in dedicated lookup tables with proper normalization.

The design draws from how MISP structures its MySQL schema (events, attributes, objects, correlations as separate tables) but applies full third-normal-form discipline. It also incorporates patterns from OpenCTI's STIX-native storage, but trades the graph layer for pure relational integrity. This is the approach a compliance-focused organization would choose when audit trail integrity, query predictability, and strict referential constraints are paramount.

This architecture is well-suited for organizations with strong DBA teams who value data integrity guarantees, need to generate compliance reports with standard SQL, and prefer explicit schema evolution over flexible-but-ambiguous JSON columns.

**Best for:** Regulated environments (financial SOCs, government CERTs) that need provable data integrity and straightforward SQL reporting.

**Trade-offs:**
- Pro: Maximum referential integrity; every relationship is enforced by the database
- Pro: Straightforward SQL queries without JSON path expressions
- Pro: Standard PostgreSQL tooling for backup, replication, and monitoring
- Pro: Schema changes are explicit and version-controlled via migrations
- Con: High table count (~50-60 tables) increases migration complexity
- Con: Adding a new STIX custom object type requires a schema migration
- Con: Many JOIN operations for cross-entity queries (e.g., "all indicators linked to a threat actor via a campaign")
- Con: STIX custom properties require schema changes rather than flexible storage

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| STIX 2.1 | Each SDO/SCO type maps 1:1 to a table; all required/optional properties are columns |
| TAXII 2.1 | `taxii_collection` and `taxii_api_root` tables model the server-side TAXII topology |
| MITRE ATT&CK | `attack_technique`, `attack_tactic`, `attack_mitigation` reference tables with ATT&CK IDs |
| TLP 2.0 | `tlp_marking` lookup table with the four TLP colours; FK from all intelligence objects |
| ISO 3166 | `country` reference table for Location SDO jurisdiction codes |
| VERIS | `veris_action`, `veris_actor`, `veris_asset` lookup tables for incident classification |
| OpenIOC | `openioic_indicator` table for legacy IOC format ingestion before STIX normalization |

---

## Core Infrastructure Tables

```sql
-- ============================================================
-- IDENTITY & ACCESS
-- ============================================================

CREATE TABLE organization (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    sector          TEXT,                          -- e.g., 'financial-services', 'government'
    country_code    CHAR(2),                       -- ISO 3166-1 alpha-2
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app_user (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id),
    email           TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE role (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,           -- 'admin', 'analyst', 'viewer', 'api_consumer'
    description     TEXT,
    permissions     TEXT[] NOT NULL DEFAULT '{}'     -- array of permission strings
);

CREATE TABLE user_role (
    user_id         UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id         UUID NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by      UUID REFERENCES app_user(id),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE api_key (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    key_hash        TEXT NOT NULL,                  -- SHA-256 of the API key
    name            TEXT NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_key_user ON api_key(user_id);
CREATE INDEX idx_app_user_org ON app_user(organization_id);
```

## STIX Reference Data Tables

```sql
-- ============================================================
-- REFERENCE / LOOKUP TABLES
-- ============================================================

CREATE TABLE tlp_marking (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tlp_level       TEXT NOT NULL UNIQUE,           -- 'TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'
    definition       TEXT NOT NULL,
    color_hex       CHAR(7) NOT NULL
);

CREATE TABLE kill_chain_phase (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kill_chain_name TEXT NOT NULL,                  -- e.g., 'mitre-attack', 'lockheed-martin-cyber-kill-chain'
    phase_name      TEXT NOT NULL,                  -- e.g., 'reconnaissance', 'initial-access'
    phase_order     INTEGER NOT NULL,
    UNIQUE (kill_chain_name, phase_name)
);

CREATE TABLE attack_tactic (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id         TEXT NOT NULL UNIQUE,           -- e.g., 'x-mitre-tactic--TA0001'
    name            TEXT NOT NULL,
    description     TEXT,
    external_id     TEXT NOT NULL,                  -- e.g., 'TA0001'
    url             TEXT
);

CREATE TABLE attack_technique (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id         TEXT NOT NULL UNIQUE,           -- e.g., 'attack-pattern--<uuid>'
    name            TEXT NOT NULL,
    description     TEXT,
    external_id     TEXT NOT NULL,                  -- e.g., 'T1566.001'
    is_subtechnique BOOLEAN NOT NULL DEFAULT false,
    parent_id       UUID REFERENCES attack_technique(id),
    url             TEXT
);

CREATE TABLE attack_technique_tactic (
    technique_id    UUID NOT NULL REFERENCES attack_technique(id) ON DELETE CASCADE,
    tactic_id       UUID NOT NULL REFERENCES attack_tactic(id) ON DELETE CASCADE,
    PRIMARY KEY (technique_id, tactic_id)
);

CREATE TABLE country (
    code            CHAR(2) PRIMARY KEY,           -- ISO 3166-1 alpha-2
    name            TEXT NOT NULL,
    region          TEXT,                           -- e.g., 'Europe', 'Asia'
    sub_region      TEXT                            -- e.g., 'Western Europe'
);
```

## STIX Domain Objects (SDOs)

```sql
-- ============================================================
-- STIX DOMAIN OBJECTS
-- ============================================================

-- Common columns shared by all SDOs are repeated per table
-- (PostgreSQL lacks table inheritance that preserves FK integrity well)

CREATE TABLE threat_actor (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,       -- 'threat-actor--<uuid>'
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    threat_actor_types  TEXT[],                     -- e.g., '{nation-state, criminal}'
    aliases             TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    sophistication      TEXT,                       -- 'none','minimal','intermediate','advanced','expert','innovator','strategic'
    resource_level      TEXT,                       -- 'individual','club','contest','team','organization','government'
    primary_motivation  TEXT,                       -- 'accidental','coercion','dominance','ideology','notoriety','organizational-gain','personal-gain','personal-satisfaction','revenge','unpredictable'
    secondary_motivations TEXT[],
    goals               TEXT[],
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_threat_actor_stix ON threat_actor(stix_id);
CREATE INDEX idx_threat_actor_name ON threat_actor USING gin(to_tsvector('english', name));
CREATE INDEX idx_threat_actor_first_seen ON threat_actor(first_seen);

CREATE TABLE campaign (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    aliases             TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    objective           TEXT,
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_campaign_stix ON campaign(stix_id);
CREATE INDEX idx_campaign_name ON campaign USING gin(to_tsvector('english', name));

CREATE TABLE intrusion_set (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    aliases             TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    goals               TEXT[],
    resource_level      TEXT,
    primary_motivation  TEXT,
    secondary_motivations TEXT[],
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE malware (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    malware_types       TEXT[],                     -- e.g., '{ransomware, trojan}'
    is_family           BOOLEAN NOT NULL DEFAULT false,
    aliases             TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    operating_system_refs TEXT[],                   -- STIX IDs of SCOs
    architecture_execution_envs TEXT[],
    implementation_languages TEXT[],
    capabilities        TEXT[],
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_malware_stix ON malware(stix_id);
CREATE INDEX idx_malware_types ON malware USING gin(malware_types);

CREATE TABLE attack_pattern (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    aliases             TEXT[],
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE attack_pattern_kill_chain (
    attack_pattern_id   UUID NOT NULL REFERENCES attack_pattern(id) ON DELETE CASCADE,
    kill_chain_phase_id UUID NOT NULL REFERENCES kill_chain_phase(id) ON DELETE CASCADE,
    PRIMARY KEY (attack_pattern_id, kill_chain_phase_id)
);

CREATE TABLE indicator (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT,
    description         TEXT,
    indicator_types     TEXT[],                     -- e.g., '{malicious-activity, anomalous-activity}'
    pattern             TEXT NOT NULL,              -- STIX pattern expression, e.g., "[ipv4-addr:value = '203.0.113.0']"
    pattern_type        TEXT NOT NULL,              -- 'stix', 'pcre', 'sigma', 'snort', 'yara'
    pattern_version     TEXT,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ,
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_indicator_stix ON indicator(stix_id);
CREATE INDEX idx_indicator_pattern_type ON indicator(pattern_type);
CREATE INDEX idx_indicator_valid_from ON indicator(valid_from);
CREATE INDEX idx_indicator_valid_until ON indicator(valid_until);
CREATE INDEX idx_indicator_types ON indicator USING gin(indicator_types);

CREATE TABLE indicator_kill_chain (
    indicator_id        UUID NOT NULL REFERENCES indicator(id) ON DELETE CASCADE,
    kill_chain_phase_id UUID NOT NULL REFERENCES kill_chain_phase(id) ON DELETE CASCADE,
    PRIMARY KEY (indicator_id, kill_chain_phase_id)
);

CREATE TABLE vulnerability (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    cve_id              TEXT,                       -- e.g., 'CVE-2024-12345'
    cvss_score          NUMERIC(3,1),
    cvss_vector         TEXT,
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_vulnerability_cve ON vulnerability(cve_id);

CREATE TABLE tool (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    tool_types          TEXT[],                     -- e.g., '{remote-access, credential-exploitation}'
    aliases             TEXT[],
    tool_version        TEXT,
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE infrastructure (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    infrastructure_types TEXT[],                    -- e.g., '{command-and-control, botnet}'
    aliases             TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE course_of_action (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    action_type         TEXT,
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity_sdo (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    identity_class      TEXT,                       -- 'individual', 'group', 'system', 'organization', 'class', 'unknown'
    sectors             TEXT[],
    contact_information TEXT,
    roles               TEXT[],
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE location (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT,
    description         TEXT,
    latitude            NUMERIC(9,6),
    longitude           NUMERIC(9,6),
    precision_meters    NUMERIC,
    region              TEXT,                       -- UN M.49 region
    country             CHAR(2) REFERENCES country(code),
    administrative_area TEXT,
    city                TEXT,
    street_address      TEXT,
    postal_code         TEXT,
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE report (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT NOT NULL,
    description         TEXT,
    report_types        TEXT[],                     -- e.g., '{threat-report, campaign-report}'
    published           TIMESTAMPTZ NOT NULL,
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Junction table: which STIX objects does a report reference?
CREATE TABLE report_object_ref (
    report_id           UUID NOT NULL REFERENCES report(id) ON DELETE CASCADE,
    ref_stix_id         TEXT NOT NULL,              -- STIX ID of referenced object
    ref_object_type     TEXT NOT NULL,              -- e.g., 'threat-actor', 'indicator'
    PRIMARY KEY (report_id, ref_stix_id)
);

CREATE TABLE grouping (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    name                TEXT,
    description         TEXT,
    context             TEXT NOT NULL,              -- 'suspicious-activity', 'malware-analysis', 'unspecified'
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE note (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    abstract            TEXT,
    content             TEXT NOT NULL,
    authors             TEXT[],
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE opinion (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    explanation         TEXT,
    opinion_value       TEXT NOT NULL,              -- 'strongly-disagree','disagree','neutral','agree','strongly-agree'
    authors             TEXT[],
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## STIX Cyber Observable Objects (SCOs)

```sql
-- ============================================================
-- STIX CYBER OBSERVABLE OBJECTS
-- ============================================================

CREATE TABLE observable_ipv4 (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    value               INET NOT NULL,
    resolves_to_refs    TEXT[],                     -- STIX IDs of mac-addr SCOs
    belongs_to_refs     TEXT[],                     -- STIX IDs of autonomous-system SCOs
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_obs_ipv4_value ON observable_ipv4(value);

CREATE TABLE observable_ipv6 (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    value               INET NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_obs_ipv6_value ON observable_ipv6(value);

CREATE TABLE observable_domain (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    value               TEXT NOT NULL,
    resolves_to_refs    TEXT[],
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_obs_domain_value ON observable_domain(value);

CREATE TABLE observable_url (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    value               TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_obs_url_value ON observable_url USING hash(value);

CREATE TABLE observable_email_addr (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    value               TEXT NOT NULL,
    display_name        TEXT,
    belongs_to_ref      TEXT,                       -- STIX ID of user-account SCO
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_obs_email_value ON observable_email_addr(value);

CREATE TABLE observable_file (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    name                TEXT,
    size                BIGINT,
    md5_hash            CHAR(32),
    sha1_hash           CHAR(40),
    sha256_hash         CHAR(64),
    sha512_hash         CHAR(128),
    mime_type           TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_obs_file_sha256 ON observable_file(sha256_hash);
CREATE INDEX idx_obs_file_md5 ON observable_file(md5_hash);
CREATE INDEX idx_obs_file_sha1 ON observable_file(sha1_hash);

CREATE TABLE observable_autonomous_system (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    number              INTEGER NOT NULL,
    name                TEXT,
    rir                 TEXT,                       -- Regional Internet Registry
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_obs_asn_number ON observable_autonomous_system(number);
```

## STIX Relationship Objects (SROs)

```sql
-- ============================================================
-- STIX RELATIONSHIP OBJECTS
-- ============================================================

CREATE TABLE stix_relationship (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    relationship_type   TEXT NOT NULL,              -- e.g., 'indicates', 'uses', 'attributed-to', 'targets'
    description         TEXT,
    source_ref          TEXT NOT NULL,              -- STIX ID of source object
    source_type         TEXT NOT NULL,              -- e.g., 'indicator', 'threat-actor'
    target_ref          TEXT NOT NULL,              -- STIX ID of target object
    target_type         TEXT NOT NULL,              -- e.g., 'malware', 'attack-pattern'
    start_time          TIMESTAMPTZ,
    stop_time           TIMESTAMPTZ,
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked             BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_rel_source ON stix_relationship(source_ref);
CREATE INDEX idx_rel_target ON stix_relationship(target_ref);
CREATE INDEX idx_rel_type ON stix_relationship(relationship_type);
CREATE INDEX idx_rel_source_type ON stix_relationship(source_type, relationship_type);
CREATE INDEX idx_rel_target_type ON stix_relationship(target_type, relationship_type);

CREATE TABLE sighting (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    description         TEXT,
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    count               INTEGER,
    sighting_of_ref     TEXT NOT NULL,              -- STIX ID of the SDO being sighted
    sighting_of_type    TEXT NOT NULL,
    observed_data_refs  TEXT[],                     -- STIX IDs of observed-data SDOs
    where_sighted_refs  TEXT[],                     -- STIX IDs of identity SDOs
    summary             BOOLEAN NOT NULL DEFAULT false,
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_marking_id      UUID REFERENCES tlp_marking(id),
    created_by_ref      UUID REFERENCES app_user(id),
    created             TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sighting_of ON sighting(sighting_of_ref);
CREATE INDEX idx_sighting_first_seen ON sighting(first_seen);
```

## Feed Management & TAXII

```sql
-- ============================================================
-- FEED MANAGEMENT & TAXII
-- ============================================================

CREATE TABLE feed_source (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    source_type     TEXT NOT NULL,                  -- 'taxii', 'misp', 'csv', 'stix_bundle', 'api'
    url             TEXT,
    auth_type       TEXT,                           -- 'api_key', 'basic', 'oauth2', 'certificate'
    auth_config     TEXT,                           -- encrypted credentials reference
    polling_interval_minutes INTEGER DEFAULT 60,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_poll_at    TIMESTAMPTZ,
    last_poll_status TEXT,                          -- 'success', 'error', 'partial'
    error_message   TEXT,
    organization_id UUID NOT NULL REFERENCES organization(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE feed_ingestion_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_source_id  UUID NOT NULL REFERENCES feed_source(id),
    started_at      TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ,
    status          TEXT NOT NULL,                  -- 'running', 'success', 'error', 'partial'
    objects_received INTEGER DEFAULT 0,
    objects_created  INTEGER DEFAULT 0,
    objects_updated  INTEGER DEFAULT 0,
    objects_skipped  INTEGER DEFAULT 0,
    error_message   TEXT
);

CREATE INDEX idx_feed_log_source ON feed_ingestion_log(feed_source_id, started_at DESC);

CREATE TABLE taxii_collection (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id   TEXT NOT NULL UNIQUE,           -- TAXII collection ID
    title           TEXT NOT NULL,
    description     TEXT,
    can_read        BOOLEAN NOT NULL DEFAULT true,
    can_write       BOOLEAN NOT NULL DEFAULT false,
    media_types     TEXT[] DEFAULT '{application/stix+json;version=2.1}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## Detection Rules & AI Enrichment

```sql
-- ============================================================
-- DETECTION RULES
-- ============================================================

CREATE TABLE detection_rule (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    rule_type       TEXT NOT NULL,                  -- 'yara', 'sigma', 'snort', 'suricata'
    rule_content    TEXT NOT NULL,                  -- the actual rule text
    version         INTEGER NOT NULL DEFAULT 1,
    severity        TEXT,                           -- 'low', 'medium', 'high', 'critical'
    is_ai_generated BOOLEAN NOT NULL DEFAULT false,
    source_indicator_id UUID REFERENCES indicator(id),
    created_by_ref  UUID REFERENCES app_user(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_detection_rule_type ON detection_rule(rule_type);

-- ============================================================
-- AI ENRICHMENT
-- ============================================================

CREATE TABLE ai_enrichment_job (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type        TEXT NOT NULL,                  -- 'ioc_extraction', 'confidence_scoring', 'rule_generation', 'report_summary'
    input_type      TEXT NOT NULL,                  -- 'report', 'indicator', 'threat_actor', 'raw_text'
    input_ref       TEXT,                           -- STIX ID or text reference
    status          TEXT NOT NULL DEFAULT 'pending',-- 'pending', 'running', 'completed', 'failed'
    result_summary  TEXT,
    objects_created INTEGER DEFAULT 0,
    model_used      TEXT,                           -- e.g., 'claude-4-sonnet', 'gpt-4o'
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    created_by_ref  UUID REFERENCES app_user(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- AUDIT LOG
-- ============================================================

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES app_user(id),
    action          TEXT NOT NULL,                  -- 'create', 'update', 'delete', 'view', 'export', 'share'
    object_type     TEXT NOT NULL,                  -- e.g., 'indicator', 'threat_actor', 'report'
    object_id       TEXT NOT NULL,                  -- STIX ID or internal UUID
    details         TEXT,
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_user ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_object ON audit_log(object_type, object_id);
CREATE INDEX idx_audit_time ON audit_log(created_at DESC);
```

## Example Queries

```sql
-- Find all indicators linked to a specific threat actor through any relationship chain
SELECT i.name, i.pattern, i.pattern_type, i.confidence, i.valid_from
FROM indicator i
JOIN stix_relationship r ON r.target_ref = i.stix_id
WHERE r.source_ref = (SELECT stix_id FROM threat_actor WHERE name = 'Lazarus Group')
  AND r.relationship_type = 'indicates'
  AND i.valid_until > now()
ORDER BY i.confidence DESC;

-- Find all ATT&CK techniques used by a campaign
SELECT at.name, at.external_id, at.description
FROM attack_technique at
JOIN stix_relationship r ON r.target_ref = at.stix_id
JOIN campaign c ON c.stix_id = r.source_ref
WHERE c.name = 'Operation Blackbird'
  AND r.relationship_type = 'uses';

-- Multi-hop: threat actor -> campaign -> malware -> attack patterns
SELECT DISTINCT ta.name AS actor, c.name AS campaign, m.name AS malware, ap.name AS technique
FROM threat_actor ta
JOIN stix_relationship r1 ON r1.source_ref = ta.stix_id AND r1.relationship_type = 'attributed-to'
JOIN campaign c ON c.stix_id = r1.target_ref
JOIN stix_relationship r2 ON r2.source_ref = c.stix_id AND r2.relationship_type = 'uses'
JOIN malware m ON m.stix_id = r2.target_ref
JOIN stix_relationship r3 ON r3.source_ref = m.stix_id AND r3.relationship_type = 'uses'
JOIN attack_pattern ap ON ap.stix_id = r3.target_ref;
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Identity & Access | 5 | organization, app_user, role, user_role, api_key |
| Reference Data | 5 | tlp_marking, kill_chain_phase, attack_tactic, attack_technique, country |
| Reference Junctions | 1 | attack_technique_tactic |
| STIX Domain Objects | 15 | One per SDO type plus junction tables |
| STIX Cyber Observables | 7 | IPv4, IPv6, domain, URL, email, file, AS |
| STIX Relationships | 2 | stix_relationship, sighting |
| Feed Management | 3 | feed_source, feed_ingestion_log, taxii_collection |
| Detection & AI | 3 | detection_rule, ai_enrichment_job, audit_log |
| **Total** | **~41** | Additional SCO tables needed for full STIX coverage |

---

## Key Design Decisions

1. **One table per STIX object type** rather than a single polymorphic table. This allows type-specific columns, constraints, and indexes at the cost of more tables and more complex cross-type queries.

2. **STIX IDs stored as TEXT** alongside internal UUIDs. The internal UUID is the primary key for joins; the STIX ID (`threat-actor--<uuid>`) is a unique indexed column for STIX interoperability and import/export.

3. **Relationships use STIX ID references** rather than internal UUID foreign keys. This is necessary because a relationship can reference any SDO or SCO type, and PostgreSQL cannot enforce a FK across 20+ tables. The `source_type` and `target_type` columns enable application-level validation.

4. **TLP marking as a foreign key** on every intelligence object. This enforces that every piece of intelligence has a sharing classification, which is critical for TAXII-based sharing compliance.

5. **Separate audit_log table** with denormalized fields rather than database triggers. This allows the application to capture context (user agent, IP) that triggers cannot access.

6. **Full-text search indexes** on name fields using GIN indexes with `to_tsvector`. This enables fast text search across threat actors, campaigns, and indicators without a separate search engine.

7. **Observable tables use native PostgreSQL types** where possible (INET for IP addresses, CHAR(64) for SHA-256 hashes). This enables type-safe queries and proper indexing.

8. **No table inheritance or partitioning** in the base schema. PostgreSQL table inheritance breaks foreign key integrity, and partitioning is better applied later based on observed query patterns (likely by `created_at` for time-range queries on indicators).
