# Data Model Suggestion 4: Graph-Relational (Property Graph + PostgreSQL)

> Project: Threat Intelligence Platform · Created: 2026-05-19

## Philosophy

This approach uses a property graph layer as the primary model for threat intelligence entities and their relationships, backed by PostgreSQL relational tables for operational concerns (users, feeds, detection rules, audit). The graph layer consists of two core tables -- `graph_node` and `graph_edge` -- that implement a property graph model directly in PostgreSQL, using JSONB for node/edge properties and PostgreSQL's `ltree` extension for hierarchical path queries (e.g., MITRE ATT&CK tactic/technique/sub-technique trees).

This design is directly inspired by OpenCTI, which uses a knowledge graph as its primary data representation. The STIX 2.1 standard is fundamentally a graph: objects are nodes, relationships and sightings are edges, and the value of threat intelligence lies in the connections between entities (threat actor -> uses -> malware -> exploits -> vulnerability -> targets -> identity). A graph-native model makes these multi-hop relationship queries first-class operations rather than expensive multi-table JOINs.

The key innovation of this model is that it implements the graph in PostgreSQL rather than requiring a separate graph database like Neo4j. This avoids the operational complexity of running two databases while still enabling graph traversal via recursive CTEs. For organizations that outgrow PostgreSQL's graph capabilities, the `graph_node` / `graph_edge` schema maps directly to Neo4j's labeled property graph model, providing a migration path.

**Best for:** Organizations where relationship analysis is the primary use case -- threat actor attribution, campaign tracking, infrastructure pivoting, conflict-of-interest detection, supply chain analysis. Also ideal for teams that want OpenCTI-style knowledge graph visualization.

**Trade-offs:**
- Pro: Multi-hop relationship queries are natural (recursive CTEs or graph traversal)
- Pro: "Find all paths between X and Y" queries are first-class operations
- Pro: Adding new entity types or relationship types requires no schema changes
- Pro: Natural fit for graph visualization UIs (each node/edge maps to a visual element)
- Pro: Migration path to dedicated graph database if needed
- Con: Recursive CTEs can be slow for deep traversals (>5 hops) on large graphs
- Con: No relational constraints on node/edge properties (JSONB validation is application-side)
- Con: Query syntax for graph traversal is less intuitive than Cypher (Neo4j) or GQL
- Con: Property graph in PostgreSQL lacks native graph query optimizations (no cost-based graph planner)
- Con: Aggregate/statistical queries require extracting properties from JSONB

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| STIX 2.1 | Each SDO/SCO becomes a `graph_node`; each SRO becomes a `graph_edge`; STIX types map to node labels |
| TAXII 2.1 | Nodes exported as STIX objects; edges exported as STIX relationships; bundles assembled from subgraph queries |
| MITRE ATT&CK | ATT&CK tactics/techniques stored as nodes with `ltree` paths (e.g., `mitre.ta0001.t1566.001`) for hierarchical queries |
| TLP 2.0 | TLP level stored as a property on every node; graph queries can filter by TLP for sharing compliance |
| ISO 3166 | Location nodes carry ISO 3166 country codes; geographic queries use node properties |
| GQL/ISO 39075 | The graph schema is designed to be compatible with the emerging ISO GQL standard for property graphs |

---

## Graph Layer

```sql
-- ============================================================
-- GRAPH LAYER — Property Graph in PostgreSQL
-- ============================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS ltree;    -- for hierarchical path queries
CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- for trigram similarity search

-- ============================================================
-- GRAPH NODES — Every STIX object is a node
-- ============================================================

CREATE TABLE graph_node (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id         TEXT NOT NULL UNIQUE,           -- e.g., 'threat-actor--<uuid>'
    node_type       TEXT NOT NULL,                  -- STIX type: 'threat-actor', 'indicator', 'malware', 'ipv4-addr', etc.
    node_class      TEXT NOT NULL,                  -- 'sdo', 'sco', 'smo'
    name            TEXT,                           -- display name (NULL for some SCOs)
    labels          TEXT[] NOT NULL DEFAULT '{}',   -- additional classification labels beyond STIX type
    -- Example labels: '{apt, nation-state, financial-sector}'

    -- Core indexed properties extracted from JSONB for fast filtering
    confidence      INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_level       TEXT,
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    valid_from      TIMESTAMPTZ,
    valid_until     TIMESTAMPTZ,
    is_revoked      BOOLEAN NOT NULL DEFAULT false,

    -- Observable value for IOC matching
    observable_value TEXT,

    -- Hierarchical path for ATT&CK-style taxonomies
    taxonomy_path   LTREE,
    -- Examples:
    -- 'mitre.enterprise.ta0001.t1566.001'  (Initial Access > Phishing > Spearphishing Attachment)
    -- 'mitre.enterprise.ta0005.t1055'      (Defense Evasion > Process Injection)
    -- 'veris.action.hacking'               (VERIS Action > Hacking)

    -- Full properties as JSONB (the complete STIX object)
    properties      JSONB NOT NULL,
    -- Example for threat-actor node:
    -- {
    --   "type": "threat-actor",
    --   "id": "threat-actor--b3486bf4-...",
    --   "name": "Lazarus Group",
    --   "threat_actor_types": ["nation-state"],
    --   "aliases": ["Hidden Cobra", "Zinc", "Diamond Sleet"],
    --   "sophistication": "expert",
    --   "resource_level": "government",
    --   "primary_motivation": "organizational-gain",
    --   "goals": ["financial theft", "espionage"],
    --   "confidence": 95
    -- }

    -- Metadata
    organization_id UUID NOT NULL,
    feed_source_id  UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Primary indexes
CREATE INDEX idx_gn_stix_id ON graph_node(stix_id);
CREATE INDEX idx_gn_type ON graph_node(node_type);
CREATE INDEX idx_gn_class ON graph_node(node_class);
CREATE INDEX idx_gn_labels ON graph_node USING gin(labels);
CREATE INDEX idx_gn_org ON graph_node(organization_id);

-- Search indexes
CREATE INDEX idx_gn_name_fts ON graph_node USING gin(to_tsvector('english', name)) WHERE name IS NOT NULL;
CREATE INDEX idx_gn_name_trgm ON graph_node USING gin(name gin_trgm_ops) WHERE name IS NOT NULL;

-- Property indexes
CREATE INDEX idx_gn_confidence ON graph_node(confidence DESC) WHERE confidence IS NOT NULL;
CREATE INDEX idx_gn_tlp ON graph_node(tlp_level) WHERE tlp_level IS NOT NULL;
CREATE INDEX idx_gn_first_seen ON graph_node(first_seen) WHERE first_seen IS NOT NULL;
CREATE INDEX idx_gn_valid_from ON graph_node(valid_from) WHERE valid_from IS NOT NULL;

-- Observable lookup
CREATE INDEX idx_gn_obs_value ON graph_node(observable_value) WHERE observable_value IS NOT NULL;

-- Taxonomy path (ltree)
CREATE INDEX idx_gn_taxonomy ON graph_node USING gist(taxonomy_path) WHERE taxonomy_path IS NOT NULL;

-- JSONB containment
CREATE INDEX idx_gn_props ON graph_node USING gin(properties jsonb_path_ops);

-- ============================================================
-- GRAPH EDGES — Every STIX relationship/sighting is an edge
-- ============================================================

CREATE TABLE graph_edge (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id         TEXT UNIQUE,                    -- STIX relationship ID (NULL for inferred edges)
    edge_type       TEXT NOT NULL,                  -- STIX relationship_type or 'sighting'
    -- Common edge_types:
    -- 'uses', 'indicates', 'attributed-to', 'targets', 'mitigates',
    -- 'derived-from', 'duplicate-of', 'related-to', 'located-at',
    -- 'based-on', 'delivers', 'exploits', 'variant-of',
    -- 'sighting', 'member-of', 'subtechnique-of'

    source_node_id  UUID NOT NULL REFERENCES graph_node(id) ON DELETE CASCADE,
    target_node_id  UUID NOT NULL REFERENCES graph_node(id) ON DELETE CASCADE,

    -- Edge properties
    confidence      INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tlp_level       TEXT,
    start_time      TIMESTAMPTZ,
    stop_time       TIMESTAMPTZ,
    is_revoked      BOOLEAN NOT NULL DEFAULT false,
    is_inferred     BOOLEAN NOT NULL DEFAULT false, -- true for AI-inferred relationships
    inference_score NUMERIC(4,3),                   -- AI confidence for inferred edges (0.000 to 1.000)

    -- Full edge properties as JSONB
    properties      JSONB NOT NULL DEFAULT '{}',
    -- Example for sighting edge:
    -- {
    --   "count": 5,
    --   "observed_data_refs": ["observed-data--..."],
    --   "where_sighted_refs": ["identity--..."],
    --   "summary": false
    -- }

    -- Metadata
    organization_id UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Graph traversal indexes (critical for performance)
CREATE INDEX idx_ge_source ON graph_edge(source_node_id);
CREATE INDEX idx_ge_target ON graph_edge(target_node_id);
CREATE INDEX idx_ge_type ON graph_edge(edge_type);
CREATE INDEX idx_ge_source_type ON graph_edge(source_node_id, edge_type);
CREATE INDEX idx_ge_target_type ON graph_edge(target_node_id, edge_type);
CREATE INDEX idx_ge_org ON graph_edge(organization_id);

-- Composite index for bi-directional traversal
CREATE INDEX idx_ge_both_nodes ON graph_edge(source_node_id, target_node_id);

-- Partial index for non-revoked, non-inferred edges (most common query)
CREATE INDEX idx_ge_active ON graph_edge(source_node_id, target_node_id, edge_type)
    WHERE is_revoked = false;
```

## Operational Tables (Relational)

```sql
-- ============================================================
-- IDENTITY & ACCESS (standard relational)
-- ============================================================

CREATE TABLE organization (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    sector          TEXT,
    country_code    CHAR(2),
    settings        JSONB NOT NULL DEFAULT '{}',
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
    preferences     JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE role (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    permissions     JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_role (
    user_id         UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id         UUID NOT NULL REFERENCES role(id) ON DELETE CASCADE,
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

-- ============================================================
-- FEED MANAGEMENT
-- ============================================================

CREATE TABLE feed_source (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    source_type     TEXT NOT NULL,
    url             TEXT,
    auth_config     JSONB,
    polling_config  JSONB NOT NULL DEFAULT '{}',
    filter_config   JSONB NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_poll_at    TIMESTAMPTZ,
    last_poll_status TEXT,
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
    error_details   JSONB
);

CREATE INDEX idx_fil_source ON feed_ingestion_log(feed_source_id, started_at DESC);

CREATE TABLE taxii_collection (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id   TEXT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    description     TEXT,
    can_read        BOOLEAN NOT NULL DEFAULT true,
    can_write       BOOLEAN NOT NULL DEFAULT false,
    organization_id UUID NOT NULL REFERENCES organization(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- DETECTION RULES
-- ============================================================

CREATE TABLE detection_rule (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    rule_type       TEXT NOT NULL,
    rule_content    TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    severity        TEXT,
    is_ai_generated BOOLEAN NOT NULL DEFAULT false,
    source_node_ids UUID[],                         -- graph_node IDs that informed this rule
    metadata        JSONB NOT NULL DEFAULT '{}',
    organization_id UUID NOT NULL REFERENCES organization(id),
    created_by      UUID REFERENCES app_user(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- AI ENRICHMENT
-- ============================================================

CREATE TABLE ai_enrichment_job (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    input_config    JSONB NOT NULL,
    result          JSONB,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    nodes_created   UUID[],                         -- graph_node IDs created by this job
    edges_created   UUID[],                         -- graph_edge IDs created by this job
    organization_id UUID NOT NULL REFERENCES organization(id),
    created_by      UUID REFERENCES app_user(id),
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
    changes         JSONB,
    context         JSONB,
    organization_id UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_user ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_time ON audit_log(created_at DESC);
```

## Example Graph Queries

```sql
-- ============================================================
-- SINGLE-HOP: All malware used by a specific threat actor
-- ============================================================
SELECT
    m.name AS malware_name,
    m.properties->>'malware_types' AS types,
    e.confidence AS relationship_confidence,
    e.edge_type
FROM graph_node ta
JOIN graph_edge e ON e.source_node_id = ta.id
JOIN graph_node m ON m.id = e.target_node_id
WHERE ta.name = 'Lazarus Group'
  AND ta.node_type = 'threat-actor'
  AND e.edge_type = 'uses'
  AND m.node_type = 'malware'
  AND e.is_revoked = false;

-- ============================================================
-- MULTI-HOP: All paths from a threat actor to targeted industries
-- (threat-actor -> uses -> malware -> targets -> identity[sector])
-- ============================================================
SELECT
    ta.name AS actor,
    m.name AS malware,
    v.name AS vulnerability,
    target.name AS target_org,
    target.properties->>'sectors' AS sectors
FROM graph_node ta
JOIN graph_edge e1 ON e1.source_node_id = ta.id AND e1.edge_type = 'uses'
JOIN graph_node m ON m.id = e1.target_node_id AND m.node_type = 'malware'
JOIN graph_edge e2 ON e2.source_node_id = m.id AND e2.edge_type = 'exploits'
JOIN graph_node v ON v.id = e2.target_node_id AND v.node_type = 'vulnerability'
JOIN graph_edge e3 ON e3.source_node_id = m.id AND e3.edge_type = 'targets'
JOIN graph_node target ON target.id = e3.target_node_id AND target.node_type = 'identity'
WHERE ta.name = 'Lazarus Group'
  AND ta.node_type = 'threat-actor';

-- ============================================================
-- RECURSIVE CTE: Find all nodes within N hops of a starting node
-- (e.g., "everything related to this indicator")
-- ============================================================
WITH RECURSIVE reachable AS (
    -- Base case: the starting node
    SELECT
        n.id,
        n.stix_id,
        n.node_type,
        n.name,
        0 AS depth,
        ARRAY[n.id] AS path
    FROM graph_node n
    WHERE n.stix_id = 'indicator--a1b2c3d4-e5f6-7890-abcd-ef1234567890'

    UNION ALL

    -- Recursive: follow edges in both directions
    SELECT
        next_node.id,
        next_node.stix_id,
        next_node.node_type,
        next_node.name,
        r.depth + 1,
        r.path || next_node.id
    FROM reachable r
    JOIN graph_edge e ON (e.source_node_id = r.id OR e.target_node_id = r.id)
                     AND e.is_revoked = false
    JOIN graph_node next_node ON next_node.id = CASE
        WHEN e.source_node_id = r.id THEN e.target_node_id
        ELSE e.source_node_id
    END
    WHERE r.depth < 3                              -- max 3 hops
      AND NOT next_node.id = ANY(r.path)           -- prevent cycles
)
SELECT DISTINCT stix_id, node_type, name, depth
FROM reachable
ORDER BY depth, node_type;

-- ============================================================
-- LTREE: Find all sub-techniques of a MITRE ATT&CK technique
-- ============================================================
SELECT name, properties->>'external_id' AS attack_id, taxonomy_path
FROM graph_node
WHERE taxonomy_path <@ 'mitre.enterprise.ta0001.t1566'  -- all descendants of T1566
  AND node_type = 'attack-pattern'
ORDER BY taxonomy_path;

-- ============================================================
-- SHORTEST PATH: Find shortest connection between two entities
-- ============================================================
WITH RECURSIVE paths AS (
    SELECT
        n.id AS current_id,
        ARRAY[n.id] AS node_path,
        ARRAY[]::uuid[] AS edge_path,
        0 AS depth
    FROM graph_node n
    WHERE n.stix_id = 'threat-actor--actor1-uuid'

    UNION ALL

    SELECT
        next_node.id,
        p.node_path || next_node.id,
        p.edge_path || e.id,
        p.depth + 1
    FROM paths p
    JOIN graph_edge e ON e.source_node_id = p.current_id AND e.is_revoked = false
    JOIN graph_node next_node ON next_node.id = e.target_node_id
    WHERE p.depth < 5
      AND NOT next_node.id = ANY(p.node_path)
)
SELECT
    node_path,
    edge_path,
    depth
FROM paths
WHERE current_id = (SELECT id FROM graph_node WHERE stix_id = 'malware--malware1-uuid')
ORDER BY depth
LIMIT 1;

-- ============================================================
-- GRAPH STATISTICS: Node degree analysis (most connected entities)
-- ============================================================
SELECT
    n.name,
    n.node_type,
    n.confidence,
    COUNT(DISTINCT e_out.id) AS outgoing_edges,
    COUNT(DISTINCT e_in.id) AS incoming_edges,
    COUNT(DISTINCT e_out.id) + COUNT(DISTINCT e_in.id) AS total_degree
FROM graph_node n
LEFT JOIN graph_edge e_out ON e_out.source_node_id = n.id AND e_out.is_revoked = false
LEFT JOIN graph_edge e_in ON e_in.target_node_id = n.id AND e_in.is_revoked = false
WHERE n.node_type IN ('threat-actor', 'malware', 'campaign')
  AND n.is_revoked = false
GROUP BY n.id, n.name, n.node_type, n.confidence
ORDER BY total_degree DESC
LIMIT 20;

-- ============================================================
-- INFERRED RELATIONSHIPS: AI-suggested edges with confidence
-- ============================================================
SELECT
    src.name AS source_name,
    src.node_type AS source_type,
    e.edge_type,
    tgt.name AS target_name,
    tgt.node_type AS target_type,
    e.inference_score,
    e.properties->>'inference_reason' AS reason
FROM graph_edge e
JOIN graph_node src ON src.id = e.source_node_id
JOIN graph_node tgt ON tgt.id = e.target_node_id
WHERE e.is_inferred = true
  AND e.inference_score >= 0.7
ORDER BY e.inference_score DESC;
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Graph Layer | 2 | graph_node, graph_edge (the core of the model) |
| Identity & Access | 5 | organization, app_user, role, user_role, api_key |
| Feed Management | 3 | feed_source, feed_ingestion_log, taxii_collection |
| Detection & AI | 2 | detection_rule, ai_enrichment_job |
| Audit | 1 | audit_log |
| **Total** | **~13** | Lowest table count; complexity is in graph queries |

---

## Key Design Decisions

1. **Property graph in PostgreSQL** rather than a dedicated graph database. This avoids the operational complexity of running Neo4j alongside PostgreSQL while enabling graph traversal through recursive CTEs. The schema is designed so that migration to Neo4j (or any LPG database) is straightforward: each `graph_node` row becomes a Neo4j node, each `graph_edge` row becomes a Neo4j relationship.

2. **`ltree` extension for hierarchical taxonomies**. MITRE ATT&CK has a deep hierarchy (tactic > technique > sub-technique). The `ltree` extension enables queries like "find all sub-techniques of T1566" with a single index-backed operation, avoiding recursive CTEs for hierarchical lookups.

3. **Foreign keys from edges to nodes** (`ON DELETE CASCADE`). Unlike the normalized model where relationships reference STIX IDs as TEXT, this model uses proper UUID foreign keys between `graph_edge` and `graph_node`. This ensures referential integrity: you cannot have an edge pointing to a deleted node.

4. **`is_inferred` flag and `inference_score` on edges**. This is unique to the graph model and supports the AI-native features of the platform. When the AI engine detects a probable relationship (e.g., two malware samples share infrastructure), it creates an inferred edge with a confidence score. Analysts can then confirm or reject the inference.

5. **Bi-directional index strategy**. Both `source_node_id` and `target_node_id` have individual indexes plus a composite index. This supports efficient graph traversal in both directions (outgoing edges from a node and incoming edges to a node).

6. **Labels array for multi-classification**. Beyond the primary `node_type` (which maps to STIX type), nodes can carry additional labels like `apt`, `financial-sector`, `critical-infrastructure`. The GIN index on the labels array enables fast filtering across classifications.

7. **Trigram index for fuzzy name search**. The `pg_trgm` extension enables similarity-based search on threat actor and malware names, which is important when analysts search for entities with slightly different spellings or transliterations (e.g., "Lazarus" vs "Lazurus" vs "LAZARUS").

8. **No separate tables for STIX SDO types**. All STIX domain objects and cyber observables are stored as `graph_node` rows differentiated by `node_type`. This keeps the graph traversal simple (all queries go through the same two tables) at the cost of losing type-specific database constraints.
