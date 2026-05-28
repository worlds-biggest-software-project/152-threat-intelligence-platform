# Data Model Suggestion 3: Hybrid Relational + JSONB

> Project: Threat Intelligence Platform · Created: 2026-05-19

## Philosophy

This approach uses a moderate number of relational tables for the structural backbone (users, feeds, relationships, detection rules) but stores STIX object properties in JSONB columns rather than breaking every STIX property into its own relational column. The key insight is that STIX 2.1 defines 18 SDO types and 18 SCO types, each with different properties, and many organizations extend STIX with custom properties. Rather than maintaining 36+ tables with rigid schemas, this model uses a unified `stix_object` table where the core indexable properties (type, name, confidence, timestamps, TLP) are relational columns, and the full STIX JSON payload lives in a JSONB column alongside them.

This pattern is used successfully by platforms like MISP (which stores attributes with flexible type/value pairs) and is a natural fit for PostgreSQL's mature JSONB support with GIN indexes, containment queries, and JSON path expressions. It provides the rapid development speed of a document store with the relational integrity of PostgreSQL for cross-object queries and access control.

The hybrid approach is particularly well-suited for a threat intelligence platform because STIX objects vary significantly by type (a Threat Actor has `sophistication` and `resource_level`; an Indicator has `pattern` and `valid_from`; a File observable has `hashes`). A hybrid model avoids the combinatorial explosion of columns across many tables while still enabling fast queries on the fields that analysts actually filter by.

**Best for:** Rapid MVP development, multi-feed environments where STIX objects arrive with unpredictable custom extensions, and teams that want schema flexibility without abandoning relational integrity for relationships and access control.

**Trade-offs:**
- Pro: Dramatically fewer tables (~15 vs ~40+); simpler migrations
- Pro: Custom STIX extensions stored without schema changes
- Pro: Full STIX JSON round-trips perfectly (import -> store -> export with no data loss)
- Pro: PostgreSQL JSONB indexes enable fast queries on nested properties
- Pro: Easier to ingest diverse feed formats without pre-mapping every field
- Con: JSONB queries are less intuitive than simple column access for developers unfamiliar with PostgreSQL JSON operators
- Con: No database-level constraints on STIX-specific fields inside JSONB (application must validate)
- Con: JSONB storage is larger than equivalent normalized columns for frequently-accessed fields
- Con: Complex JSONB aggregation queries can be slower than equivalent relational joins

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| STIX 2.1 | Full STIX JSON stored verbatim in `stix_data` JSONB column; core properties extracted to indexed columns |
| TAXII 2.1 | `taxii_collection` table manages TAXII server topology; STIX bundles served directly from stored JSON |
| MITRE ATT&CK | ATT&CK objects stored as STIX objects in the unified table; `external_references` in JSONB carry ATT&CK IDs |
| TLP 2.0 | Extracted to `tlp_level` indexed column; also preserved in `stix_data.object_marking_refs` |
| ISO 3166 | Location objects carry country codes in JSONB; `country` reference table for validation |
| MISP Core Format | MISP events map to STIX bundles; MISP-specific extensions stored in JSONB without loss |

---

## Core Intelligence Tables

```sql
-- ============================================================
-- UNIFIED STIX OBJECT STORE
-- ============================================================
-- This single table stores ALL STIX Domain Objects and Cyber Observables.
-- Core properties are extracted to indexed columns for fast queries.
-- The full STIX JSON is stored in stix_data for lossless round-tripping.

CREATE TABLE stix_object (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id         TEXT NOT NULL UNIQUE,           -- e.g., 'threat-actor--<uuid>', 'indicator--<uuid>'
    stix_type       TEXT NOT NULL,                  -- e.g., 'threat-actor', 'indicator', 'malware', 'ipv4-addr'
    spec_version    TEXT NOT NULL DEFAULT '2.1',
    object_class    TEXT NOT NULL,                  -- 'sdo', 'sco', 'smo'

    -- Extracted searchable properties (common across most SDOs)
    name            TEXT,                           -- NULL for SCOs that lack a name
    description     TEXT,
    confidence      INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_level       TEXT,                           -- 'TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'
    created_by_ref  TEXT,                           -- STIX ID of the identity that created this

    -- Temporal properties
    stix_created    TIMESTAMPTZ,                    -- STIX 'created' timestamp
    stix_modified   TIMESTAMPTZ,                    -- STIX 'modified' timestamp
    first_seen      TIMESTAMPTZ,                    -- available on threat-actor, campaign, malware, infrastructure
    last_seen       TIMESTAMPTZ,
    valid_from      TIMESTAMPTZ,                    -- indicator-specific
    valid_until     TIMESTAMPTZ,                    -- indicator-specific

    -- Indicator-specific extracted fields
    pattern         TEXT,                           -- STIX pattern expression
    pattern_type    TEXT,                           -- 'stix', 'pcre', 'sigma', 'snort', 'yara'

    -- Observable-specific extracted fields
    observable_value TEXT,                          -- Normalized value for SCOs (IP, domain, hash, URL, email)

    -- Status
    is_revoked      BOOLEAN NOT NULL DEFAULT false,
    is_expired      BOOLEAN NOT NULL DEFAULT false, -- set by scheduled job when valid_until < now()

    -- Full STIX JSON payload — the source of truth for all type-specific properties
    stix_data       JSONB NOT NULL,
    -- Example for threat-actor:
    -- {
    --   "type": "threat-actor",
    --   "id": "threat-actor--b3486bf4-...",
    --   "name": "Lazarus Group",
    --   "threat_actor_types": ["nation-state"],
    --   "aliases": ["Hidden Cobra", "Zinc"],
    --   "sophistication": "expert",
    --   "resource_level": "government",
    --   "primary_motivation": "organizational-gain",
    --   "goals": ["financial theft", "espionage"],
    --   "external_references": [...],
    --   "object_marking_refs": ["marking-definition--613f2e26-..."]
    -- }

    -- Metadata
    feed_source_id  UUID,                           -- which feed ingested this (NULL if analyst-created)
    organization_id UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Primary lookup indexes
CREATE INDEX idx_stix_obj_stix_id ON stix_object(stix_id);
CREATE INDEX idx_stix_obj_type ON stix_object(stix_type);
CREATE INDEX idx_stix_obj_class ON stix_object(object_class);
CREATE INDEX idx_stix_obj_tlp ON stix_object(tlp_level);
CREATE INDEX idx_stix_obj_confidence ON stix_object(confidence DESC) WHERE confidence IS NOT NULL;
CREATE INDEX idx_stix_obj_org ON stix_object(organization_id);

-- Text search
CREATE INDEX idx_stix_obj_name_fts ON stix_object USING gin(to_tsvector('english', name)) WHERE name IS NOT NULL;
CREATE INDEX idx_stix_obj_desc_fts ON stix_object USING gin(to_tsvector('english', description)) WHERE description IS NOT NULL;

-- Temporal indexes
CREATE INDEX idx_stix_obj_first_seen ON stix_object(first_seen) WHERE first_seen IS NOT NULL;
CREATE INDEX idx_stix_obj_last_seen ON stix_object(last_seen) WHERE last_seen IS NOT NULL;
CREATE INDEX idx_stix_obj_valid_from ON stix_object(valid_from) WHERE valid_from IS NOT NULL;
CREATE INDEX idx_stix_obj_valid_until ON stix_object(valid_until) WHERE valid_until IS NOT NULL;
CREATE INDEX idx_stix_obj_modified ON stix_object(stix_modified DESC);

-- Indicator-specific indexes
CREATE INDEX idx_stix_obj_pattern_type ON stix_object(pattern_type) WHERE pattern_type IS NOT NULL;

-- Observable-specific indexes (for fast IOC matching)
CREATE INDEX idx_stix_obj_obs_value ON stix_object(observable_value) WHERE observable_value IS NOT NULL;
CREATE INDEX idx_stix_obj_obs_type_value ON stix_object(stix_type, observable_value) WHERE observable_value IS NOT NULL;

-- JSONB GIN index for containment queries on the full payload
CREATE INDEX idx_stix_obj_data_gin ON stix_object USING gin(stix_data jsonb_path_ops);

-- Partial indexes for common filtered queries
CREATE INDEX idx_stix_obj_active_indicators ON stix_object(valid_from, confidence DESC)
    WHERE stix_type = 'indicator' AND is_revoked = false AND is_expired = false;
CREATE INDEX idx_stix_obj_threat_actors ON stix_object(name, confidence DESC)
    WHERE stix_type = 'threat-actor' AND is_revoked = false;
```

## Relationships

```sql
-- ============================================================
-- STIX RELATIONSHIPS (relational — these are the graph edges)
-- ============================================================

CREATE TABLE stix_relationship (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    relationship_type   TEXT NOT NULL,              -- 'indicates', 'uses', 'attributed-to', 'targets', etc.
    description         TEXT,
    source_ref          TEXT NOT NULL,              -- STIX ID
    source_type         TEXT NOT NULL,
    target_ref          TEXT NOT NULL,              -- STIX ID
    target_type         TEXT NOT NULL,
    start_time          TIMESTAMPTZ,
    stop_time           TIMESTAMPTZ,
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_level           TEXT,
    is_revoked          BOOLEAN NOT NULL DEFAULT false,
    stix_data           JSONB,                      -- full STIX relationship JSON if additional properties exist
    organization_id     UUID NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_rel_source ON stix_relationship(source_ref);
CREATE INDEX idx_rel_target ON stix_relationship(target_ref);
CREATE INDEX idx_rel_type ON stix_relationship(relationship_type);
CREATE INDEX idx_rel_source_target ON stix_relationship(source_ref, target_ref);
CREATE INDEX idx_rel_org ON stix_relationship(organization_id);

CREATE TABLE sighting (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL UNIQUE,
    spec_version        TEXT NOT NULL DEFAULT '2.1',
    description         TEXT,
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    count               INTEGER DEFAULT 1,
    sighting_of_ref     TEXT NOT NULL,              -- STIX ID of the SDO being sighted
    observed_data_refs  TEXT[],
    where_sighted_refs  TEXT[],
    confidence          INTEGER CHECK (confidence BETWEEN 0 AND 100),
    is_revoked          BOOLEAN NOT NULL DEFAULT false,
    stix_data           JSONB,
    organization_id     UUID NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sighting_of ON sighting(sighting_of_ref);
CREATE INDEX idx_sighting_time ON sighting(first_seen, last_seen);
```

## Identity, Access & Organization

```sql
-- ============================================================
-- IDENTITY & ACCESS
-- ============================================================

CREATE TABLE organization (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    sector          TEXT,
    country_code    CHAR(2),
    settings        JSONB NOT NULL DEFAULT '{}',    -- org-specific configuration
    -- Example settings:
    -- {
    --   "default_tlp": "TLP:AMBER",
    --   "auto_expire_indicators": true,
    --   "indicator_expiry_days": 90,
    --   "enabled_feed_types": ["taxii", "misp", "csv"],
    --   "tech_stack": ["kubernetes", "aws", "nodejs"]
    -- }
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
    preferences     JSONB NOT NULL DEFAULT '{}',    -- user-specific UI preferences
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE role (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    permissions     JSONB NOT NULL DEFAULT '[]',
    -- Example: ["stix:read", "stix:write", "feed:manage", "detection:export", "admin:users"]
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_role (
    user_id         UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id         UUID NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE api_key (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    key_hash        TEXT NOT NULL,
    name            TEXT NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## Feed Management

```sql
-- ============================================================
-- FEED MANAGEMENT
-- ============================================================

CREATE TABLE feed_source (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    source_type     TEXT NOT NULL,                  -- 'taxii', 'misp', 'csv', 'stix_bundle', 'api', 'manual'
    url             TEXT,
    auth_config     JSONB,                          -- encrypted reference or config
    -- Example for TAXII:
    -- { "type": "api_key", "header": "Authorization", "vault_ref": "secret/feeds/taxii-1" }
    polling_config  JSONB NOT NULL DEFAULT '{}',
    -- Example:
    -- { "interval_minutes": 60, "max_objects_per_poll": 10000, "deduplicate": true }
    filter_config   JSONB NOT NULL DEFAULT '{}',
    -- Example:
    -- { "stix_types": ["indicator", "malware"], "min_confidence": 50, "tlp_max": "TLP:AMBER" }
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_poll_at    TIMESTAMPTZ,
    last_poll_status TEXT,
    stats           JSONB NOT NULL DEFAULT '{}',
    -- Example:
    -- { "total_objects_ingested": 145032, "last_24h": 342, "error_rate_7d": 0.02 }
    organization_id UUID NOT NULL REFERENCES organization(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE feed_ingestion_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_source_id  UUID NOT NULL REFERENCES feed_source(id),
    started_at      TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ,
    status          TEXT NOT NULL,
    stats           JSONB NOT NULL DEFAULT '{}',
    -- Example:
    -- { "received": 500, "created": 120, "updated": 350, "skipped": 30, "errors": 0 }
    error_details   JSONB
);

CREATE INDEX idx_feed_log_source ON feed_ingestion_log(feed_source_id, started_at DESC);

CREATE TABLE taxii_collection (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id   TEXT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    description     TEXT,
    can_read        BOOLEAN NOT NULL DEFAULT true,
    can_write       BOOLEAN NOT NULL DEFAULT false,
    media_types     TEXT[] DEFAULT '{application/stix+json;version=2.1}',
    organization_id UUID NOT NULL REFERENCES organization(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## Detection Rules & AI

```sql
-- ============================================================
-- DETECTION RULES
-- ============================================================

CREATE TABLE detection_rule (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    rule_type       TEXT NOT NULL,                  -- 'yara', 'sigma', 'snort', 'suricata'
    rule_content    TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    severity        TEXT,
    is_ai_generated BOOLEAN NOT NULL DEFAULT false,
    source_stix_ids TEXT[],                         -- STIX IDs that informed this rule
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- Example:
    -- { "mitre_techniques": ["T1566.001"], "target_platforms": ["windows"], "false_positive_rate": 0.05 }
    organization_id UUID NOT NULL REFERENCES organization(id),
    created_by      UUID REFERENCES app_user(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_detection_rule_type ON detection_rule(rule_type);

-- ============================================================
-- AI ENRICHMENT
-- ============================================================

CREATE TABLE ai_enrichment_job (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    input_config    JSONB NOT NULL,
    -- Example for IOC extraction:
    -- { "source_type": "report_url", "url": "https://...", "extract_types": ["ipv4-addr", "domain-name", "file"] }
    result          JSONB,
    -- Example:
    -- { "objects_extracted": 12, "stix_ids_created": ["indicator--...", "indicator--..."], "model": "claude-4-sonnet" }
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    created_by      UUID REFERENCES app_user(id),
    organization_id UUID NOT NULL REFERENCES organization(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- AUDIT LOG
-- ============================================================

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES app_user(id),
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    changes         JSONB,                          -- { "field": "confidence", "old": 60, "new": 85 }
    context         JSONB,                          -- { "ip": "10.0.0.1", "user_agent": "...", "source": "api" }
    organization_id UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_user ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_time ON audit_log(created_at DESC);
CREATE INDEX idx_audit_org ON audit_log(organization_id, created_at DESC);

-- ============================================================
-- WORKSPACE & COLLABORATION
-- ============================================================

CREATE TABLE workspace (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    workspace_type  TEXT NOT NULL,                  -- 'investigation', 'report_draft', 'hunt'
    status          TEXT NOT NULL DEFAULT 'active', -- 'active', 'archived', 'completed'
    stix_object_refs TEXT[],                        -- STIX IDs of objects in this workspace
    config          JSONB NOT NULL DEFAULT '{}',
    organization_id UUID NOT NULL REFERENCES organization(id),
    created_by      UUID NOT NULL REFERENCES app_user(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspace_member (
    workspace_id    UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role            TEXT NOT NULL DEFAULT 'contributor', -- 'owner', 'contributor', 'viewer'
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE workspace_comment (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES app_user(id),
    content         TEXT NOT NULL,
    parent_id       UUID REFERENCES workspace_comment(id), -- threaded replies
    stix_ref        TEXT,                           -- optional: comment on specific STIX object
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## Example Queries

```sql
-- Find all nation-state threat actors with high confidence
SELECT stix_id, name, confidence, first_seen, last_seen,
       stix_data->'aliases' AS aliases,
       stix_data->>'sophistication' AS sophistication,
       stix_data->>'resource_level' AS resource_level
FROM stix_object
WHERE stix_type = 'threat-actor'
  AND stix_data @> '{"threat_actor_types": ["nation-state"]}'
  AND confidence >= 80
  AND is_revoked = false
ORDER BY confidence DESC;

-- Fast IOC lookup across all observable types
SELECT stix_id, stix_type, observable_value, stix_data
FROM stix_object
WHERE observable_value = '203.0.113.42'
  AND object_class = 'sco';

-- Find all indicators that reference a specific ATT&CK technique
-- Uses JSONB containment to check external_references array
SELECT stix_id, name, pattern, pattern_type, confidence
FROM stix_object
WHERE stix_type = 'indicator'
  AND stix_data @> '{"external_references": [{"source_name": "mitre-attack", "external_id": "T1566.001"}]}'
  AND is_revoked = false
  AND is_expired = false;

-- Cross-entity traversal: threat actor -> uses -> malware
SELECT
    ta.name AS threat_actor,
    ta.stix_data->>'sophistication' AS sophistication,
    r.relationship_type,
    m.name AS malware,
    m.stix_data->'malware_types' AS malware_types
FROM stix_object ta
JOIN stix_relationship r ON r.source_ref = ta.stix_id
JOIN stix_object m ON m.stix_id = r.target_ref
WHERE ta.stix_type = 'threat-actor'
  AND r.relationship_type = 'uses'
  AND m.stix_type = 'malware'
  AND ta.is_revoked = false
ORDER BY ta.confidence DESC;

-- Full-text search across all intelligence objects
SELECT stix_id, stix_type, name, confidence, tlp_level
FROM stix_object
WHERE to_tsvector('english', name || ' ' || COALESCE(description, ''))
      @@ plainto_tsquery('english', 'ransomware financial institution')
  AND is_revoked = false
ORDER BY confidence DESC
LIMIT 20;

-- Export a STIX bundle for TAXII sharing (lossless round-trip)
SELECT json_build_object(
    'type', 'bundle',
    'id', 'bundle--' || gen_random_uuid(),
    'objects', json_agg(stix_data)
) AS stix_bundle
FROM stix_object
WHERE organization_id = 'org-uuid-here'
  AND tlp_level IN ('TLP:CLEAR', 'TLP:GREEN')
  AND stix_modified >= now() - INTERVAL '24 hours';
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Intelligence Store | 1 | stix_object (unified SDO + SCO) |
| Relationships | 2 | stix_relationship, sighting |
| Identity & Access | 5 | organization, app_user, role, user_role, api_key |
| Feed Management | 3 | feed_source, feed_ingestion_log, taxii_collection |
| Detection & AI | 2 | detection_rule, ai_enrichment_job |
| Audit | 1 | audit_log |
| Collaboration | 3 | workspace, workspace_member, workspace_comment |
| **Total** | **~17** | Dramatically fewer tables than the normalized approach |

---

## Key Design Decisions

1. **Single unified `stix_object` table** for all SDOs and SCOs. This is the defining choice of this model. It trades type-specific database constraints for flexibility and simplicity. The `stix_type` column differentiates objects; the `stix_data` JSONB column carries all type-specific properties.

2. **Extracted columns for high-frequency query fields**. Properties like `name`, `confidence`, `tlp_level`, `valid_from`, `valid_until`, `pattern_type`, and `observable_value` are extracted into indexed relational columns even though they also exist in `stix_data`. This gives the best of both worlds: fast indexed queries on common fields, full STIX payload for everything else.

3. **JSONB containment queries** (`@>`) for type-specific filtering. PostgreSQL's GIN index with `jsonb_path_ops` makes containment queries fast. Searching for all indicators with a specific ATT&CK technique in their `external_references` array is a single `@>` query against the index.

4. **Lossless STIX round-tripping**. Because the full STIX JSON is stored verbatim, export to STIX bundles for TAXII sharing is a simple JSON aggregation query with zero transformation. This eliminates the impedance mismatch between the database schema and the wire format.

5. **JSONB for configuration and preferences** throughout (organization settings, feed configs, AI job configs). This avoids the proliferation of narrow configuration tables while keeping the data queryable.

6. **Relationships remain relational**. Despite the JSONB approach for STIX objects, relationships are stored in a dedicated relational table with indexed `source_ref` and `target_ref` columns. This is because relationship traversal is the most performance-sensitive query pattern and benefits from relational indexes.

7. **Observable value extraction** for fast IOC matching. The `observable_value` column normalizes the "primary value" of each SCO (the IP address, domain name, hash, URL, or email) into a single indexed TEXT column. This enables sub-millisecond IOC lookups across all observable types in a single query.

8. **Workspace and collaboration tables are relational**. Collaboration features (workspaces, comments, membership) do not benefit from JSONB flexibility and are better served by standard relational patterns with foreign key integrity.
