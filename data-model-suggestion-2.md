# Data Model Suggestion 2: Event-Sourced / Audit-First (CQRS)

> Project: Threat Intelligence Platform · Created: 2026-05-19

## Philosophy

This approach treats the threat intelligence platform as an event-sourced system where every change to every piece of intelligence is recorded as an immutable event in a single append-only event store. The event store is the single source of truth. Materialized read models (views) are rebuilt from events to serve different query patterns: a relational view for analyst search, a timeline view for temporal queries, and a statistics view for dashboards.

This design is inspired by how financial trading platforms and compliance systems handle audit requirements. In the threat intelligence domain, it is uniquely powerful because intelligence is inherently temporal: an indicator that was reliable yesterday may be revoked today, a threat actor's attribution confidence changes over time, and analysts need to answer questions like "What did we know about this campaign on March 15th?" or "Who changed this indicator's confidence score and why?" Event sourcing answers these questions natively rather than through bolted-on audit tables.

The CQRS (Command Query Responsibility Segregation) pattern separates write operations (commands that produce events) from read operations (queries against materialized views). This allows the write path to be optimized for append performance while read models are tuned for specific query patterns. New read models can be added retroactively by replaying the event stream.

**Best for:** Organizations that need complete audit trails, temporal queries ("what was true on date X?"), and the ability to reconstruct the state of any intelligence object at any point in time. Ideal for government CERTs and ISACs with strict accountability requirements.

**Trade-offs:**
- Pro: Complete, immutable audit trail is automatic -- every change is an event
- Pro: Temporal queries are native ("what did we know on date X?")
- Pro: New read models can be created retroactively by replaying events
- Pro: Natural fit for AI analysis of change patterns and analyst behaviour
- Pro: Event replay enables debugging and forensic reconstruction
- Con: Higher storage requirements (every change stored, not just current state)
- Con: Eventual consistency between event store and read models
- Con: More complex application code (command handlers, event processors, projections)
- Con: Event schema evolution requires careful versioning (upcasting)
- Con: Cold-start read model rebuild can be slow for large event stores

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| STIX 2.1 | Events carry STIX object payloads; the `modified` property aligns naturally with event timestamps |
| TAXII 2.1 | TAXII polling produces `FeedObjectReceived` events; TAXII publishing reads from materialized views |
| MITRE ATT&CK | ATT&CK technique mappings stored as `TechniqueLinked`/`TechniqueUnlinked` events |
| TLP 2.0 | TLP changes are explicit events (`MarkingChanged`), enabling sharing-policy audit |
| NIST SP 800-150 | Event store naturally satisfies NIST guidance on maintaining provenance of shared intelligence |
| ISO 27001 A.5.7 | Immutable event log directly supports the threat intelligence audit requirements of ISO 27001 |
| VERIS | Incident classification events use VERIS vocabulary for categorization |

---

## Event Store (Write Model)

```sql
-- ============================================================
-- EVENT STORE — Single source of truth
-- ============================================================

CREATE TABLE event_store (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stream_id       TEXT NOT NULL,                  -- STIX ID or internal aggregate ID
    stream_type     TEXT NOT NULL,                  -- 'threat-actor', 'indicator', 'campaign', 'feed', 'user', etc.
    event_type      TEXT NOT NULL,                  -- e.g., 'ThreatActorCreated', 'IndicatorConfidenceUpdated'
    event_version   INTEGER NOT NULL DEFAULT 1,     -- schema version of this event type
    sequence_number BIGINT NOT NULL,                -- monotonically increasing per stream
    payload         JSONB NOT NULL,                 -- the event data (STIX object or delta)
    metadata        JSONB NOT NULL DEFAULT '{}',    -- { "user_id": "...", "ip": "...", "source": "feed|analyst|ai", "correlation_id": "..." }
    occurred_at     TIMESTAMPTZ NOT NULL,           -- when the real-world event happened
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(), -- when the event was stored
    UNIQUE (stream_id, sequence_number)
);

-- Partitioned by month for manageable table sizes
-- In production: CREATE TABLE event_store (...) PARTITION BY RANGE (recorded_at);

CREATE INDEX idx_event_stream ON event_store(stream_id, sequence_number);
CREATE INDEX idx_event_type ON event_store(event_type, recorded_at);
CREATE INDEX idx_event_stream_type ON event_store(stream_type, recorded_at);
CREATE INDEX idx_event_occurred ON event_store(occurred_at);
CREATE INDEX idx_event_recorded ON event_store(recorded_at);
CREATE INDEX idx_event_metadata_user ON event_store USING gin((metadata->'user_id'));

-- ============================================================
-- EVENT TYPE REGISTRY — Documents all known event types
-- ============================================================

CREATE TABLE event_type_registry (
    event_type      TEXT PRIMARY KEY,
    stream_type     TEXT NOT NULL,
    description     TEXT NOT NULL,
    payload_schema  JSONB NOT NULL,                 -- JSON Schema for the payload
    current_version INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Example event type registrations:
-- ('ThreatActorCreated',    'threat-actor', 'A new threat actor was ingested or created', {...}, 1)
-- ('ThreatActorUpdated',    'threat-actor', 'Properties of a threat actor were modified', {...}, 1)
-- ('ThreatActorRevoked',    'threat-actor', 'A threat actor was marked as revoked', {...}, 1)
-- ('IndicatorCreated',      'indicator',    'A new indicator was ingested or created', {...}, 1)
-- ('IndicatorConfidenceUpdated', 'indicator', 'Confidence score changed', {...}, 1)
-- ('IndicatorExpired',      'indicator',    'Indicator passed its valid_until date', {...}, 1)
-- ('RelationshipCreated',   'relationship', 'A STIX relationship was established', {...}, 1)
-- ('SightingRecorded',      'sighting',     'An indicator was sighted', {...}, 1)
-- ('FeedPollStarted',       'feed',         'A feed poll cycle began', {...}, 1)
-- ('FeedObjectReceived',    'feed',         'An object was received from a feed', {...}, 1)
-- ('DetectionRuleGenerated','detection',    'An AI or analyst created a detection rule', {...}, 1)
-- ('TLPMarkingChanged',     '*',            'TLP marking was changed on an object', {...}, 1)
-- ('AIEnrichmentCompleted', 'enrichment',   'An AI enrichment job finished', {...}, 1)
```

### Example Event Payloads

```json
-- ThreatActorCreated event payload:
{
  "stix_object": {
    "type": "threat-actor",
    "spec_version": "2.1",
    "id": "threat-actor--b3486bf4-4cf1-4bca-95b5-e09f8b1a68c8",
    "name": "Lazarus Group",
    "threat_actor_types": ["nation-state"],
    "aliases": ["Hidden Cobra", "Zinc", "Diamond Sleet"],
    "first_seen": "2009-01-01T00:00:00Z",
    "sophistication": "expert",
    "resource_level": "government",
    "primary_motivation": "organizational-gain",
    "confidence": 95
  },
  "source": "feed",
  "feed_source_id": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
  "tlp_marking": "TLP:GREEN"
}

-- IndicatorConfidenceUpdated event payload:
{
  "previous_confidence": 60,
  "new_confidence": 85,
  "reason": "Confirmed by analyst observation in customer environment",
  "ai_assisted": false
}

-- SightingRecorded event payload:
{
  "sighting_of_ref": "indicator--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "where_sighted": "organization--98765432-1abc-def0-1234-567890abcdef",
  "count": 3,
  "first_seen": "2026-05-18T14:30:00Z",
  "last_seen": "2026-05-18T16:45:00Z"
}
```

## Snapshot Store (Optimization)

```sql
-- ============================================================
-- SNAPSHOT STORE — Periodic snapshots to avoid full replay
-- ============================================================

CREATE TABLE snapshot_store (
    snapshot_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stream_id       TEXT NOT NULL,
    stream_type     TEXT NOT NULL,
    sequence_number BIGINT NOT NULL,                -- event sequence at time of snapshot
    state           JSONB NOT NULL,                 -- full materialized state at this point
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_snapshot_stream ON snapshot_store(stream_id, sequence_number DESC);

-- Snapshots are taken every N events per stream (e.g., every 100 events)
-- To reconstruct current state: load latest snapshot + replay events after snapshot
```

## Read Models (Materialized Views)

```sql
-- ============================================================
-- READ MODEL: Analyst Search View
-- ============================================================
-- This is the primary read model for analyst queries.
-- Rebuilt by the projection engine from events.

CREATE TABLE rm_threat_actor (
    id                  UUID PRIMARY KEY,
    stix_id             TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    description         TEXT,
    threat_actor_types  TEXT[],
    aliases             TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    sophistication      TEXT,
    resource_level      TEXT,
    primary_motivation  TEXT,
    confidence          INTEGER,
    tlp_level           TEXT,
    is_revoked          BOOLEAN NOT NULL DEFAULT false,
    event_count         INTEGER NOT NULL DEFAULT 0, -- how many events in this stream
    last_modified_by    UUID,
    last_event_at       TIMESTAMPTZ,
    created             TIMESTAMPTZ,
    modified            TIMESTAMPTZ
);

CREATE INDEX idx_rm_ta_name ON rm_threat_actor USING gin(to_tsvector('english', name));
CREATE INDEX idx_rm_ta_stix ON rm_threat_actor(stix_id);

CREATE TABLE rm_indicator (
    id                  UUID PRIMARY KEY,
    stix_id             TEXT NOT NULL UNIQUE,
    name                TEXT,
    description         TEXT,
    indicator_types     TEXT[],
    pattern             TEXT NOT NULL,
    pattern_type        TEXT NOT NULL,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ,
    confidence          INTEGER,
    tlp_level           TEXT,
    is_revoked          BOOLEAN NOT NULL DEFAULT false,
    is_expired          BOOLEAN NOT NULL DEFAULT false,
    sighting_count      INTEGER NOT NULL DEFAULT 0,
    last_sighted_at     TIMESTAMPTZ,
    event_count         INTEGER NOT NULL DEFAULT 0,
    last_modified_by    UUID,
    last_event_at       TIMESTAMPTZ,
    created             TIMESTAMPTZ,
    modified            TIMESTAMPTZ
);

CREATE INDEX idx_rm_ind_stix ON rm_indicator(stix_id);
CREATE INDEX idx_rm_ind_pattern_type ON rm_indicator(pattern_type);
CREATE INDEX idx_rm_ind_valid ON rm_indicator(valid_from, valid_until);
CREATE INDEX idx_rm_ind_confidence ON rm_indicator(confidence DESC);

CREATE TABLE rm_campaign (
    id                  UUID PRIMARY KEY,
    stix_id             TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    description         TEXT,
    aliases             TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    objective           TEXT,
    confidence          INTEGER,
    tlp_level           TEXT,
    is_revoked          BOOLEAN NOT NULL DEFAULT false,
    event_count         INTEGER NOT NULL DEFAULT 0,
    last_event_at       TIMESTAMPTZ,
    created             TIMESTAMPTZ,
    modified            TIMESTAMPTZ
);

CREATE TABLE rm_malware (
    id                  UUID PRIMARY KEY,
    stix_id             TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    description         TEXT,
    malware_types       TEXT[],
    is_family           BOOLEAN NOT NULL DEFAULT false,
    aliases             TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    confidence          INTEGER,
    tlp_level           TEXT,
    is_revoked          BOOLEAN NOT NULL DEFAULT false,
    event_count         INTEGER NOT NULL DEFAULT 0,
    last_event_at       TIMESTAMPTZ,
    created             TIMESTAMPTZ,
    modified            TIMESTAMPTZ
);

CREATE TABLE rm_relationship (
    id                  UUID PRIMARY KEY,
    stix_id             TEXT NOT NULL UNIQUE,
    relationship_type   TEXT NOT NULL,
    source_ref          TEXT NOT NULL,
    source_type         TEXT NOT NULL,
    target_ref          TEXT NOT NULL,
    target_type         TEXT NOT NULL,
    start_time          TIMESTAMPTZ,
    stop_time           TIMESTAMPTZ,
    confidence          INTEGER,
    is_revoked          BOOLEAN NOT NULL DEFAULT false,
    last_event_at       TIMESTAMPTZ,
    created             TIMESTAMPTZ,
    modified            TIMESTAMPTZ
);

CREATE INDEX idx_rm_rel_source ON rm_relationship(source_ref);
CREATE INDEX idx_rm_rel_target ON rm_relationship(target_ref);
CREATE INDEX idx_rm_rel_type ON rm_relationship(relationship_type);

-- ============================================================
-- READ MODEL: Observable Lookup (optimized for IOC matching)
-- ============================================================

CREATE TABLE rm_observable (
    id                  UUID PRIMARY KEY,
    stix_id             TEXT NOT NULL UNIQUE,
    observable_type     TEXT NOT NULL,              -- 'ipv4-addr', 'domain-name', 'file', 'url', 'email-addr'
    value               TEXT NOT NULL,              -- normalized string value for fast lookup
    value_hash          TEXT NOT NULL,              -- SHA-256 of normalized value for exact-match index
    additional_fields   JSONB,                      -- type-specific fields (hashes for files, etc.)
    first_seen_in_feed  TIMESTAMPTZ,
    last_seen_in_feed   TIMESTAMPTZ,
    sighting_count      INTEGER NOT NULL DEFAULT 0,
    linked_indicator_count INTEGER NOT NULL DEFAULT 0,
    last_event_at       TIMESTAMPTZ
);

CREATE INDEX idx_rm_obs_value_hash ON rm_observable(value_hash);
CREATE INDEX idx_rm_obs_type_value ON rm_observable(observable_type, value);
CREATE INDEX idx_rm_obs_type ON rm_observable(observable_type);

-- ============================================================
-- READ MODEL: Timeline View (for temporal analysis)
-- ============================================================

CREATE TABLE rm_timeline (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id             TEXT NOT NULL,
    object_type         TEXT NOT NULL,
    object_name         TEXT,
    event_type          TEXT NOT NULL,
    event_summary       TEXT,                       -- human-readable summary of what changed
    actor_user_id       UUID,                       -- who caused this change
    actor_display_name  TEXT,
    source              TEXT,                       -- 'feed', 'analyst', 'ai', 'system'
    occurred_at         TIMESTAMPTZ NOT NULL,
    recorded_at         TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_rm_timeline_stix ON rm_timeline(stix_id, occurred_at DESC);
CREATE INDEX idx_rm_timeline_type ON rm_timeline(object_type, occurred_at DESC);
CREATE INDEX idx_rm_timeline_time ON rm_timeline(occurred_at DESC);

-- ============================================================
-- READ MODEL: Dashboard Statistics
-- ============================================================

CREATE TABLE rm_daily_stats (
    stat_date           DATE NOT NULL,
    organization_id     UUID NOT NULL,
    metric_name         TEXT NOT NULL,              -- 'indicators_created', 'sightings_recorded', 'feeds_polled', etc.
    metric_value        BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (stat_date, organization_id, metric_name)
);

CREATE INDEX idx_rm_stats_date ON rm_daily_stats(stat_date DESC);
```

## Command & Projection Infrastructure

```sql
-- ============================================================
-- PROJECTION TRACKING — Tracks which events each read model has processed
-- ============================================================

CREATE TABLE projection_checkpoint (
    projection_name TEXT PRIMARY KEY,               -- e.g., 'analyst_search', 'observable_lookup', 'timeline', 'dashboard'
    last_event_id   UUID,
    last_event_at   TIMESTAMPTZ,
    events_processed BIGINT NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'running', -- 'running', 'paused', 'rebuilding', 'error'
    error_message   TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- DEAD LETTER QUEUE — Events that failed processing
-- ============================================================

CREATE TABLE dead_letter_event (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID NOT NULL,                  -- references event_store.event_id
    projection_name TEXT NOT NULL,
    error_message   TEXT NOT NULL,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    max_retries     INTEGER NOT NULL DEFAULT 3,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- IDENTITY & ACCESS (same as write model — not event-sourced)
-- ============================================================

CREATE TABLE organization (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    sector          TEXT,
    country_code    CHAR(2),
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
    name            TEXT NOT NULL UNIQUE,
    permissions     TEXT[] NOT NULL DEFAULT '{}'
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
-- FEED CONFIGURATION (not event-sourced — operational config)
-- ============================================================

CREATE TABLE feed_source (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    url             TEXT,
    auth_type       TEXT,
    polling_interval_minutes INTEGER DEFAULT 60,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    organization_id UUID NOT NULL REFERENCES organization(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## Example Queries

```sql
-- TEMPORAL QUERY: What was the confidence of an indicator on a specific date?
-- Replay events up to that date to reconstruct state
SELECT payload->>'new_confidence' AS confidence_at_date
FROM event_store
WHERE stream_id = 'indicator--a1b2c3d4-e5f6-7890-abcd-ef1234567890'
  AND event_type IN ('IndicatorCreated', 'IndicatorConfidenceUpdated')
  AND occurred_at <= '2026-03-15T00:00:00Z'
ORDER BY sequence_number DESC
LIMIT 1;

-- WHO CHANGED WHAT: Audit trail for a specific threat actor
SELECT
    e.event_type,
    e.occurred_at,
    e.metadata->>'user_id' AS changed_by,
    u.display_name,
    e.metadata->>'source' AS source,
    e.payload
FROM event_store e
LEFT JOIN app_user u ON u.id = (e.metadata->>'user_id')::uuid
WHERE e.stream_id = 'threat-actor--b3486bf4-4cf1-4bca-95b5-e09f8b1a68c8'
ORDER BY e.sequence_number ASC;

-- ANALYTICS: How many indicators were created per day from feeds vs. analysts?
SELECT
    DATE(occurred_at) AS day,
    metadata->>'source' AS source,
    COUNT(*) AS count
FROM event_store
WHERE event_type = 'IndicatorCreated'
  AND occurred_at >= now() - INTERVAL '30 days'
GROUP BY DATE(occurred_at), metadata->>'source'
ORDER BY day DESC;

-- FAST IOC LOOKUP: Check if an IP was ever observed (uses read model)
SELECT stix_id, observable_type, value, sighting_count, last_seen_in_feed
FROM rm_observable
WHERE value_hash = encode(sha256('203.0.113.42'::bytea), 'hex')
  AND observable_type = 'ipv4-addr';

-- TIMELINE VIEW: Recent activity on all threat actors
SELECT object_name, event_type, event_summary, actor_display_name, source, occurred_at
FROM rm_timeline
WHERE object_type = 'threat-actor'
  AND occurred_at >= now() - INTERVAL '7 days'
ORDER BY occurred_at DESC
LIMIT 50;

-- RECONSTRUCT FULL STATE: Rebuild a threat actor from events
-- (Application code does this; simplified SQL illustration)
SELECT event_type, payload, occurred_at
FROM event_store
WHERE stream_id = 'threat-actor--b3486bf4-4cf1-4bca-95b5-e09f8b1a68c8'
ORDER BY sequence_number ASC;
-- Application applies each event in order to build current state
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Event Store | 3 | event_store, event_type_registry, snapshot_store |
| Read Model: Search | 5 | rm_threat_actor, rm_indicator, rm_campaign, rm_malware, rm_relationship |
| Read Model: Observables | 1 | rm_observable (unified lookup) |
| Read Model: Timeline | 1 | rm_timeline |
| Read Model: Stats | 1 | rm_daily_stats |
| Projection Infrastructure | 2 | projection_checkpoint, dead_letter_event |
| Identity & Access | 5 | organization, app_user, role, user_role, api_key |
| Feed Configuration | 1 | feed_source |
| **Total** | **~19** | Far fewer tables; complexity is in event processing |

---

## Key Design Decisions

1. **Single event store table** rather than per-type event tables. The `stream_type` and `event_type` columns enable filtering. This keeps the write path simple and allows cross-type event queries (e.g., "all events in the last hour regardless of type").

2. **JSONB payloads** for event data rather than typed columns. This allows event schema evolution without DDL migrations. The `event_version` column enables upcasting old events to new schemas during replay.

3. **Separate `occurred_at` and `recorded_at` timestamps**. `occurred_at` is when the real-world event happened (e.g., when a feed published an indicator); `recorded_at` is when the event was stored. This distinction is critical for temporal queries.

4. **Snapshot store for performance**. Without snapshots, reconstructing a heavily-modified threat actor would require replaying hundreds of events. Snapshots every 100 events keep reconstruction fast.

5. **Read models are disposable and rebuildable**. If a read model becomes corrupted or a new query pattern is needed, the projection can be rebuilt from scratch by replaying the event store. This is the key advantage of event sourcing.

6. **Dead letter queue for failed event processing**. If a projection fails to process an event (schema mismatch, unexpected data), the event goes to the dead letter queue rather than blocking the entire projection pipeline.

7. **Identity and feed configuration are NOT event-sourced**. These are operational concerns where current state is sufficient. Event sourcing is reserved for the intelligence domain where temporal queries and audit trails matter.

8. **The event store supports partitioning by `recorded_at`**. Monthly partitions keep index sizes manageable and allow old partitions to be archived to cold storage while maintaining the complete audit trail.
