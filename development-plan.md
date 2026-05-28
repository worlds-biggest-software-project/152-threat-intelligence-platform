# Threat Intelligence Platform — Phased Development Plan

> Project: 152-threat-intelligence-platform · Created: 2026-05-25
> Purpose: Provide sufficient detail for Claude Code (Opus) to implement each phase end-to-end.

---

## Technology Decisions

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Primary language | Python 3.12+ | STIX ecosystem libraries (python-stix2, PyMISP, pycti) are Python-native; LLM SDK integration (anthropic, openai) is best supported in Python; threat intelligence analyst community is predominantly Python |
| API framework | FastAPI 0.115+ | Native OpenAPI 3.1 generation required for TAXII 2.1 endpoint documentation; async support critical for concurrent feed polling and LLM enrichment calls; Pydantic v2 integration for STIX object validation |
| Database | PostgreSQL 16+ | JSONB with GIN indexes supports the hybrid relational+JSONB data model (Suggestion 3); `pg_trgm` for fuzzy threat actor name search; INET type for IP observable queries; `ltree` available if graph queries are needed later |
| Search engine | PostgreSQL full-text search (GIN + to_tsvector) | Avoids Elasticsearch dependency for MVP; PostgreSQL FTS with GIN indexes is sufficient for the IOC search and correlation workload; can add Elasticsearch later if needed |
| Task queue | Celery 5.4+ with Redis broker | Feed polling, AI enrichment, detection rule generation, and indicator expiry are all async workloads; Celery provides scheduling (Celery Beat) for periodic feed polling; Redis also serves as cache layer |
| Cache | Redis 7+ | Sub-second IOC lookup cache for the rapid enrichment API; session store for JWT refresh tokens; rate limiting for TAXII endpoints |
| Frontend | React 19 + TypeScript 5.5 + Vite | Dashboard-heavy application with graph visualisation, MITRE ATT&CK navigator, and analyst collaboration workspaces; React ecosystem has mature graph visualisation libraries (react-force-graph, cytoscape.js) |
| CSS framework | Tailwind CSS 4 + shadcn/ui | Consistent, accessible UI components; dark mode support expected by SOC analyst user base |
| Graph visualisation | Cytoscape.js | Best-in-class for knowledge graph visualisation; supports STIX relationship graphs, ATT&CK navigator views, and campaign correlation diagrams; PostgreSQL-backed (no Neo4j dependency) |
| ORM / query builder | SQLAlchemy 2.0 (async) | Async PostgreSQL support via asyncpg; JSONB column support; Alembic for schema migrations; widely understood |
| Migration tool | Alembic 1.13+ | Standard for SQLAlchemy projects; version-controlled schema migrations |
| LLM provider | Anthropic Claude API (primary), OpenAI-compatible fallback | IOC extraction, confidence scoring, detection rule generation, and conversational query interface; provider-agnostic abstraction layer for flexibility |
| Authentication | JWT (access + refresh) with OAuth 2.0 / OIDC support | JWT for API and SPA auth; OAuth 2.0 / OIDC for SSO with enterprise identity providers (Okta, Azure AD, Keycloak) per standards.md |
| Containerisation | Docker + Docker Compose | Self-hosted deployment target matching MISP/OpenCTI patterns; multi-service orchestration (API, worker, scheduler, Redis, PostgreSQL) |
| Testing framework | pytest 8+ (backend), Vitest 3+ (frontend) | pytest-asyncio for async endpoint tests; pytest-httpx for mocked HTTP; Vitest for React component and integration tests |
| Code quality | Ruff (linter + formatter), mypy (type checking), ESLint + Prettier (frontend) | Ruff replaces flake8+black+isort; mypy strict mode for type safety on STIX data structures |
| Package manager | uv (backend), pnpm (frontend) | uv for fast Python dependency resolution; pnpm for deterministic node_modules |
| Key libraries | python-stix2 (STIX parsing), taxii2-client/taxii2-server (TAXII protocol), PyMISP (MISP feed ingestion), anthropic SDK (LLM calls), pydantic v2 (validation), httpx (async HTTP), cryptography (credential encryption) |

### Project Structure

```
threat-intelligence-platform/
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── alembic.ini
├── alembic/
│   └── versions/
├── .env.example
├── src/
│   ├── tip/
│   │   ├── __init__.py
│   │   ├── main.py                      # FastAPI application factory
│   │   ├── config.py                    # Pydantic Settings (env-based configuration)
│   │   ├── database.py                  # SQLAlchemy async engine and session
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── base.py                  # SQLAlchemy declarative base
│   │   │   ├── stix.py                  # stix_object, stix_relationship, sighting
│   │   │   ├── auth.py                  # organization, app_user, role, user_role, api_key
│   │   │   ├── feed.py                  # feed_source, feed_ingestion_log, taxii_collection
│   │   │   ├── detection.py             # detection_rule
│   │   │   ├── enrichment.py            # ai_enrichment_job
│   │   │   ├── workspace.py             # workspace, workspace_member, workspace_comment
│   │   │   └── audit.py                 # audit_log
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── stix.py                  # Pydantic models for STIX API request/response
│   │   │   ├── auth.py                  # Auth request/response schemas
│   │   │   ├── feed.py                  # Feed management schemas
│   │   │   ├── detection.py             # Detection rule schemas
│   │   │   ├── enrichment.py            # AI enrichment job schemas
│   │   │   ├── workspace.py             # Workspace schemas
│   │   │   └── taxii.py                 # TAXII 2.1 protocol schemas
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── deps.py                  # Dependency injection (current user, db session, etc.)
│   │   │   ├── v1/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── auth.py              # Authentication endpoints
│   │   │   │   ├── stix_objects.py       # STIX object CRUD + search
│   │   │   │   ├── relationships.py     # STIX relationship management
│   │   │   │   ├── indicators.py        # Indicator-specific endpoints + IOC lookup
│   │   │   │   ├── threat_actors.py     # Threat actor management
│   │   │   │   ├── feeds.py             # Feed source management
│   │   │   │   ├── detection_rules.py   # Detection rule CRUD + export
│   │   │   │   ├── enrichment.py        # AI enrichment job management
│   │   │   │   ├── workspaces.py        # Collaboration workspace endpoints
│   │   │   │   └── admin.py             # Organization, user, role management
│   │   │   └── taxii/
│   │   │       ├── __init__.py
│   │   │       ├── discovery.py         # TAXII 2.1 discovery endpoint
│   │   │       ├── api_root.py          # TAXII 2.1 API root
│   │   │       └── collections.py       # TAXII 2.1 collection endpoints
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── stix_service.py          # STIX object business logic
│   │   │   ├── feed_service.py          # Feed polling and ingestion logic
│   │   │   ├── search_service.py        # Full-text search and correlation
│   │   │   ├── detection_service.py     # Detection rule generation and export
│   │   │   ├── enrichment_service.py    # AI enrichment orchestration
│   │   │   ├── taxii_service.py         # TAXII 2.1 server logic
│   │   │   ├── auth_service.py          # Authentication and authorization
│   │   │   ├── audit_service.py         # Audit logging
│   │   │   └── workspace_service.py     # Workspace management
│   │   ├── workers/
│   │   │   ├── __init__.py
│   │   │   ├── celery_app.py            # Celery application configuration
│   │   │   ├── feed_tasks.py            # Feed polling and ingestion tasks
│   │   │   ├── enrichment_tasks.py      # AI enrichment tasks
│   │   │   ├── detection_tasks.py       # Detection rule generation tasks
│   │   │   ├── maintenance_tasks.py     # Indicator expiry, cleanup tasks
│   │   │   └── scheduler.py            # Celery Beat schedule configuration
│   │   ├── ingestion/
│   │   │   ├── __init__.py
│   │   │   ├── base.py                  # Abstract feed ingester
│   │   │   ├── taxii_ingester.py        # TAXII 2.1 client ingestion
│   │   │   ├── misp_ingester.py         # MISP feed ingestion via PyMISP
│   │   │   ├── stix_bundle_ingester.py  # STIX bundle file ingestion
│   │   │   ├── csv_ingester.py          # CSV indicator import
│   │   │   └── normalizer.py            # STIX normalization and deduplication
│   │   ├── ai/
│   │   │   ├── __init__.py
│   │   │   ├── provider.py              # LLM provider abstraction
│   │   │   ├── ioc_extractor.py         # IOC extraction from unstructured text
│   │   │   ├── confidence_scorer.py     # AI confidence scoring
│   │   │   ├── rule_generator.py        # Detection rule generation
│   │   │   ├── report_generator.py      # Finished intelligence generation
│   │   │   ├── relevance_scorer.py      # Organizational relevance scoring
│   │   │   └── prompts/
│   │   │       ├── ioc_extraction.py
│   │   │       ├── confidence_scoring.py
│   │   │       ├── rule_generation.py
│   │   │       └── report_generation.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── stix_helpers.py          # STIX ID generation, validation
│   │       ├── crypto.py                # Credential encryption, API key hashing
│   │       └── pagination.py            # Cursor-based pagination
│   └── frontend/
│       ├── package.json
│       ├── vite.config.ts
│       ├── tsconfig.json
│       ├── src/
│       │   ├── App.tsx
│       │   ├── main.tsx
│       │   ├── api/                     # API client (generated from OpenAPI)
│       │   ├── components/
│       │   │   ├── layout/
│       │   │   ├── stix/                # STIX object display components
│       │   │   ├── search/              # Search and filter components
│       │   │   ├── graph/               # Cytoscape.js graph visualisation
│       │   │   ├── attack/              # MITRE ATT&CK navigator
│       │   │   ├── detection/           # Detection rule editor/viewer
│       │   │   ├── workspace/           # Collaboration workspace components
│       │   │   └── dashboard/           # Dashboard widgets
│       │   ├── pages/
│       │   ├── hooks/
│       │   ├── stores/                  # Zustand state management
│       │   └── types/
│       └── tests/
├── tests/
│   ├── conftest.py                      # Shared fixtures (db, client, factories)
│   ├── factories/                       # Factory Boy factories for test data
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   └── fixtures/                        # Static test data (STIX bundles, CSVs)
└── docs/
    ├── api.md
    └── deployment.md
```

---

## Phase 1: Foundation — Project Scaffolding, Database, and Configuration

### Purpose

Establish the project skeleton, database schema, configuration system, and development tooling. After this phase, the application boots, connects to PostgreSQL and Redis, runs Alembic migrations, and serves a health-check endpoint. All subsequent phases build on this foundation without restructuring.

### Tasks

#### 1.1 — Project initialisation and tooling

**What**: Create the Python project with `pyproject.toml`, configure Ruff, mypy, pytest, and Docker Compose.

**Design**:

```toml
# pyproject.toml (key sections)
[project]
name = "threat-intelligence-platform"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "sqlalchemy[asyncio]>=2.0.36",
    "asyncpg>=0.30.0",
    "alembic>=1.13.0",
    "pydantic>=2.10.0",
    "pydantic-settings>=2.6.0",
    "redis>=5.2.0",
    "celery[redis]>=5.4.0",
    "httpx>=0.28.0",
    "python-stix2>=3.0.1",
    "python-jose[cryptography]>=3.3.0",
    "passlib[bcrypt]>=1.7.4",
    "cryptography>=43.0.0",
    "anthropic>=0.40.0",
]

[tool.ruff]
target-version = "py312"
line-length = 120

[tool.mypy]
python_version = "3.12"
strict = true
plugins = ["pydantic.mypy", "sqlalchemy.ext.mypy.plugin"]
```

```yaml
# docker-compose.yml
services:
  api:
    build: .
    ports: ["8000:8000"]
    environment:
      - DATABASE_URL=postgresql+asyncpg://tip:tip@db:5432/tip
      - REDIS_URL=redis://redis:6379/0
    depends_on: [db, redis]

  worker:
    build: .
    command: celery -A src.tip.workers.celery_app worker -l info
    environment:
      - DATABASE_URL=postgresql+asyncpg://tip:tip@db:5432/tip
      - REDIS_URL=redis://redis:6379/0
    depends_on: [db, redis]

  scheduler:
    build: .
    command: celery -A src.tip.workers.celery_app beat -l info
    environment:
      - REDIS_URL=redis://redis:6379/0
    depends_on: [redis]

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: tip
      POSTGRES_PASSWORD: tip
      POSTGRES_DB: tip
    ports: ["5432:5432"]
    volumes: ["pgdata:/var/lib/postgresql/data"]

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

volumes:
  pgdata:
```

**Testing**:
- `Unit: pyproject.toml is valid — uv sync succeeds with no errors`
- `Unit: ruff check passes on empty src/ directory`
- `Unit: mypy check passes on empty src/ directory`
- `Integration: docker-compose up starts all services without errors`
- `Integration: API container responds to GET /health with 200`

---

#### 1.2 — Configuration system

**What**: Implement environment-based configuration using Pydantic Settings with validation, defaults, and .env file support.

**Design**:

```python
# src/tip/config.py
from pydantic import field_validator, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="TIP_")

    # Application
    app_name: str = "Threat Intelligence Platform"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    taxii_prefix: str = "/taxii/2.1"

    # Database
    database_url: str = "postgresql+asyncpg://tip:tip@localhost:5432/tip"
    database_pool_size: int = 20
    database_max_overflow: int = 10

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_cache_ttl: int = 300  # seconds

    # Authentication
    jwt_secret_key: SecretStr
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # LLM Provider
    llm_provider: str = "anthropic"  # "anthropic" or "openai"
    anthropic_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None
    llm_model: str = "claude-sonnet-4-20250514"

    # Feed polling
    default_polling_interval_minutes: int = 60
    max_objects_per_poll: int = 10000

    # STIX defaults
    default_stix_spec_version: str = "2.1"
    default_tlp_level: str = "TLP:AMBER"

    # Pagination
    default_page_size: int = 50
    max_page_size: int = 500

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v.startswith("postgresql"):
            raise ValueError("Only PostgreSQL is supported")
        return v

def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
```

**Testing**:
- `Unit: valid env vars → Settings object with correct values`
- `Unit: missing TIP_JWT_SECRET_KEY → ValidationError with field name`
- `Unit: invalid DATABASE_URL (sqlite://...) → ValidationError "Only PostgreSQL is supported"`
- `Unit: default values applied when env vars absent (e.g., default_page_size = 50)`
- `Unit: .env file values override defaults`
- `Unit: SecretStr fields are not exposed in repr/str`

---

#### 1.3 — Database connection and SQLAlchemy setup

**What**: Create the async SQLAlchemy engine, session factory, and declarative base with common column mixins.

**Design**:

```python
# src/tip/database.py
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from datetime import datetime
from uuid import UUID, uuid4
import sqlalchemy as sa

class Base(DeclarativeBase):
    pass

class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(),
        onupdate=sa.func.now(), nullable=False
    )

class UUIDPrimaryKeyMixin:
    id: Mapped[UUID] = mapped_column(
        sa.Uuid, primary_key=True, default=uuid4
    )

engine = create_async_engine(
    settings.database_url,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    echo=settings.debug,
)

async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db_session() -> AsyncSession:
    async with async_session_factory() as session:
        yield session
```

**Testing**:
- `Integration: create_async_engine connects to PostgreSQL — session.execute(select(1)) returns 1`
- `Integration: session rollback works — uncommitted writes are not persisted`
- `Unit: TimestampMixin sets created_at and updated_at defaults`
- `Unit: UUIDPrimaryKeyMixin generates valid UUID4 primary keys`

---

#### 1.4 — Core database schema (Alembic initial migration)

**What**: Create the initial Alembic migration implementing the hybrid relational+JSONB schema from Data Model Suggestion 3, covering all core tables.

**Design**:

Implements the tables from Data Model Suggestion 3 (the Hybrid Relational + JSONB model) as SQLAlchemy ORM models. This is the chosen data model because:
1. Fewest tables (~17) reduces migration complexity
2. JSONB `stix_data` column enables lossless STIX round-tripping critical for TAXII export
3. Extracted indexed columns (name, confidence, tlp_level, valid_from, observable_value) give relational query performance on high-frequency filters
4. Custom STIX extensions stored without schema changes, essential for multi-feed ingestion

```python
# src/tip/models/stix.py
class StixObject(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "stix_object"

    stix_id: Mapped[str] = mapped_column(sa.Text, unique=True, nullable=False, index=True)
    stix_type: Mapped[str] = mapped_column(sa.Text, nullable=False, index=True)
    spec_version: Mapped[str] = mapped_column(sa.Text, nullable=False, default="2.1")
    object_class: Mapped[str] = mapped_column(sa.Text, nullable=False)  # 'sdo', 'sco', 'smo'

    name: Mapped[str | None] = mapped_column(sa.Text)
    description: Mapped[str | None] = mapped_column(sa.Text)
    confidence: Mapped[int | None] = mapped_column(sa.Integer)
    tlp_level: Mapped[str | None] = mapped_column(sa.Text, index=True)
    created_by_ref: Mapped[str | None] = mapped_column(sa.Text)

    stix_created: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    stix_modified: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    first_seen: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    valid_from: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    pattern: Mapped[str | None] = mapped_column(sa.Text)
    pattern_type: Mapped[str | None] = mapped_column(sa.Text)
    observable_value: Mapped[str | None] = mapped_column(sa.Text, index=True)

    is_revoked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    is_expired: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    stix_data: Mapped[dict] = mapped_column(sa.JSON, nullable=False)

    feed_source_id: Mapped[UUID | None] = mapped_column(sa.Uuid, sa.ForeignKey("feed_source.id"))
    organization_id: Mapped[UUID] = mapped_column(sa.Uuid, sa.ForeignKey("organization.id"), nullable=False)


class StixRelationship(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "stix_relationship"

    stix_id: Mapped[str] = mapped_column(sa.Text, unique=True, nullable=False)
    spec_version: Mapped[str] = mapped_column(sa.Text, nullable=False, default="2.1")
    relationship_type: Mapped[str] = mapped_column(sa.Text, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(sa.Text)
    source_ref: Mapped[str] = mapped_column(sa.Text, nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    target_ref: Mapped[str] = mapped_column(sa.Text, nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    start_time: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    stop_time: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    confidence: Mapped[int | None] = mapped_column(sa.Integer)
    tlp_level: Mapped[str | None] = mapped_column(sa.Text)
    is_revoked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    stix_data: Mapped[dict | None] = mapped_column(sa.JSON)
    organization_id: Mapped[UUID] = mapped_column(sa.Uuid, sa.ForeignKey("organization.id"), nullable=False)


class Sighting(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "sighting"

    stix_id: Mapped[str] = mapped_column(sa.Text, unique=True, nullable=False)
    spec_version: Mapped[str] = mapped_column(sa.Text, nullable=False, default="2.1")
    description: Mapped[str | None] = mapped_column(sa.Text)
    first_seen: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    count: Mapped[int | None] = mapped_column(sa.Integer, default=1)
    sighting_of_ref: Mapped[str] = mapped_column(sa.Text, nullable=False, index=True)
    observed_data_refs: Mapped[list | None] = mapped_column(sa.ARRAY(sa.Text))
    where_sighted_refs: Mapped[list | None] = mapped_column(sa.ARRAY(sa.Text))
    confidence: Mapped[int | None] = mapped_column(sa.Integer)
    is_revoked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    stix_data: Mapped[dict | None] = mapped_column(sa.JSON)
    organization_id: Mapped[UUID] = mapped_column(sa.Uuid, sa.ForeignKey("organization.id"), nullable=False)
```

Additional models for `organization`, `app_user`, `role`, `user_role`, `api_key`, `feed_source`, `feed_ingestion_log`, `taxii_collection`, `detection_rule`, `ai_enrichment_job`, `audit_log`, `workspace`, `workspace_member`, `workspace_comment` follow the DDL from Data Model Suggestion 3 verbatim.

**Testing**:
- `Integration: alembic upgrade head runs without errors on clean database`
- `Integration: alembic downgrade base and re-upgrade — idempotent migration`
- `Integration: insert a StixObject with stix_data JSONB → query it back, JSONB round-trips exactly`
- `Integration: unique constraint on stix_object.stix_id — duplicate insert raises IntegrityError`
- `Integration: ForeignKey from stix_object.organization_id → organization.id enforced`
- `Integration: GIN index on stix_data enables @> containment query`
- `Unit: full-text search index on name field — to_tsvector query returns matching rows`

---

#### 1.5 — FastAPI application shell and health endpoint

**What**: Create the FastAPI application factory, mount API router prefixes, configure CORS, and expose /health.

**Design**:

```python
# src/tip/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: verify database connectivity
    async with engine.begin() as conn:
        await conn.execute(sa.text("SELECT 1"))
    yield
    # Shutdown: dispose engine
    await engine.dispose()

def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Tighten in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health_router)
    app.include_router(v1_router, prefix=settings.api_v1_prefix)
    app.include_router(taxii_router, prefix=settings.taxii_prefix)
    return app

# Health endpoint
@health_router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db_session)) -> dict:
    await db.execute(sa.text("SELECT 1"))
    return {"status": "healthy", "version": "0.1.0"}
```

**Testing**:
- `Integration: GET /health → 200 {"status": "healthy", "version": "0.1.0"}`
- `Integration: GET /health with database down → 503`
- `Integration: GET /docs → 200 (Swagger UI loads)`
- `Integration: GET /openapi.json → valid OpenAPI 3.1 document`
- `Integration: CORS headers present in response for cross-origin request`

---

## Phase 2: Authentication, Authorization, and User Management

### Purpose

Implement JWT-based authentication, role-based access control, API key management, and user/organization CRUD. After this phase, the API enforces authentication on all endpoints, supports multi-tenant organizations, and provides the security foundation required by ISO 27001 A.5.7 and OWASP API Security Top 10.

### Tasks

#### 2.1 — User registration and JWT authentication

**What**: Implement user registration, login, JWT access/refresh token issuance, and token refresh flow.

**Design**:

```python
# src/tip/schemas/auth.py
from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime

class UserRegister(BaseModel):
    email: EmailStr
    display_name: str
    password: str  # min 12 chars, validated
    organization_id: UUID

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds

class UserResponse(BaseModel):
    id: UUID
    email: str
    display_name: str
    organization_id: UUID
    is_active: bool
    roles: list[str]
    created_at: datetime

# src/tip/services/auth_service.py
class AuthService:
    async def register_user(self, data: UserRegister) -> UserResponse: ...
    async def login(self, data: UserLogin) -> TokenResponse: ...
    async def refresh_token(self, refresh_token: str) -> TokenResponse: ...
    async def get_current_user(self, token: str) -> UserResponse: ...
    def verify_password(self, plain: str, hashed: str) -> bool: ...
    def create_access_token(self, user_id: UUID, roles: list[str]) -> str: ...
    def create_refresh_token(self, user_id: UUID) -> str: ...
```

API endpoints:
- `POST /api/v1/auth/register` — create user (requires admin role or first-user bootstrap)
- `POST /api/v1/auth/login` — returns TokenResponse
- `POST /api/v1/auth/refresh` — exchange refresh token for new access token
- `GET /api/v1/auth/me` — returns current user profile

JWT payload structure:
```json
{
  "sub": "user-uuid",
  "org": "organization-uuid",
  "roles": ["analyst", "admin"],
  "exp": 1716681600,
  "iat": 1716679800,
  "jti": "unique-token-id"
}
```

**Testing**:
- `Unit: valid password → bcrypt hash that verify_password accepts`
- `Unit: create_access_token → JWT with correct sub, org, roles, exp claims`
- `Unit: expired JWT → raises ExpiredTokenError`
- `Unit: tampered JWT → raises InvalidTokenError`
- `Integration: POST /auth/register with valid data → 201, user created in database`
- `Integration: POST /auth/register with duplicate email → 409 Conflict`
- `Integration: POST /auth/login with valid credentials → 200, TokenResponse with valid JWT`
- `Integration: POST /auth/login with wrong password → 401 Unauthorized`
- `Integration: POST /auth/refresh with valid refresh token → new access token`
- `Integration: POST /auth/refresh with expired refresh token → 401`
- `Integration: GET /auth/me with valid access token → user profile`
- `Integration: GET /auth/me without token → 401`

---

#### 2.2 — Role-based access control (RBAC)

**What**: Implement permission checking middleware, role assignment, and per-endpoint authorization.

**Design**:

Default roles and permissions:
```python
DEFAULT_ROLES = {
    "admin": ["*"],  # all permissions
    "analyst": [
        "stix:read", "stix:write",
        "relationship:read", "relationship:write",
        "feed:read",
        "detection:read", "detection:write", "detection:export",
        "enrichment:read", "enrichment:create",
        "workspace:read", "workspace:write",
        "search:execute",
    ],
    "viewer": [
        "stix:read", "relationship:read", "feed:read",
        "detection:read", "workspace:read", "search:execute",
    ],
    "api_consumer": [
        "stix:read", "relationship:read", "search:execute",
        "taxii:read",
    ],
}

# src/tip/api/deps.py
from fastapi import Depends, HTTPException, Security

def require_permission(permission: str):
    async def checker(current_user: UserResponse = Depends(get_current_user)):
        if not has_permission(current_user.roles, permission):
            raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
        return current_user
    return checker

# Usage in endpoints:
@router.post("/stix-objects")
async def create_stix_object(
    data: StixObjectCreate,
    user: UserResponse = Depends(require_permission("stix:write")),
    db: AsyncSession = Depends(get_db_session),
): ...
```

**Testing**:
- `Unit: admin role has_permission("stix:write") → True`
- `Unit: viewer role has_permission("stix:write") → False`
- `Unit: viewer role has_permission("stix:read") → True`
- `Integration: analyst creates STIX object → 201`
- `Integration: viewer creates STIX object → 403 "Missing permission: stix:write"`
- `Integration: admin assigns role to user → role appears in user's JWT on next login`

---

#### 2.3 — API key management

**What**: Implement API key CRUD for programmatic access, with scoped permissions and expiry.

**Design**:

```python
# src/tip/schemas/auth.py
class ApiKeyCreate(BaseModel):
    name: str
    scopes: list[str]  # subset of user's permissions
    expires_in_days: int | None = None  # None = no expiry

class ApiKeyResponse(BaseModel):
    id: UUID
    name: str
    key_prefix: str  # first 8 chars for identification
    scopes: list[str]
    expires_at: datetime | None
    created_at: datetime
    last_used_at: datetime | None

class ApiKeyCreated(ApiKeyResponse):
    api_key: str  # full key, shown only once
```

API endpoints:
- `POST /api/v1/auth/api-keys` — create API key (returns full key once)
- `GET /api/v1/auth/api-keys` — list user's API keys (prefix only)
- `DELETE /api/v1/auth/api-keys/{id}` — revoke API key

Authentication header: `Authorization: Bearer tip_<base64-key>`

**Testing**:
- `Unit: API key generation produces 32-byte random key with tip_ prefix`
- `Unit: API key hash is SHA-256, not reversible`
- `Integration: create API key → key returned, hashed value stored in database`
- `Integration: authenticate with valid API key → request succeeds, last_used_at updated`
- `Integration: authenticate with expired API key → 401`
- `Integration: authenticate with revoked API key → 401`
- `Integration: API key scopes restrict access — key with ["stix:read"] cannot POST`

---

#### 2.4 — Organization management and multi-tenancy

**What**: Implement organization CRUD and tenant isolation — all data queries scoped by organization_id.

**Design**:

```python
# src/tip/schemas/auth.py
class OrganizationCreate(BaseModel):
    name: str
    description: str | None = None
    sector: str | None = None  # 'financial-services', 'government', 'healthcare', etc.
    country_code: str | None = None  # ISO 3166-1 alpha-2
    settings: dict = {}

class OrganizationResponse(BaseModel):
    id: UUID
    name: str
    sector: str | None
    country_code: str | None
    settings: dict
    created_at: datetime
```

Tenant isolation enforcement:
```python
# src/tip/api/deps.py
async def get_org_scoped_query(
    model: type[Base],
    db: AsyncSession,
    user: UserResponse,
) -> Select:
    """Always filter by the current user's organization_id."""
    return sa.select(model).where(model.organization_id == user.organization_id)
```

**Testing**:
- `Integration: user in org A queries STIX objects → sees only org A data`
- `Integration: user in org A cannot access org B STIX objects even with valid stix_id`
- `Integration: create organization → 201 with UUID`
- `Integration: organization settings JSONB stores and retrieves tech_stack array`

---

#### 2.5 — Audit logging

**What**: Implement automatic audit logging for all state-changing operations per ISO 27001 and NIST SP 800-150 requirements.

**Design**:

```python
# src/tip/services/audit_service.py
class AuditService:
    async def log(
        self,
        db: AsyncSession,
        user_id: UUID | None,
        action: str,          # 'create', 'update', 'delete', 'view', 'export', 'share', 'login', 'login_failed'
        resource_type: str,   # 'stix_object', 'indicator', 'feed_source', 'user', etc.
        resource_id: str,
        changes: dict | None = None,   # {"field": "confidence", "old": 60, "new": 85}
        context: dict | None = None,   # {"ip": "...", "user_agent": "...", "source": "api"}
        organization_id: UUID | None = None,
    ) -> None: ...

# FastAPI middleware for automatic context capture:
class AuditMiddleware:
    async def __call__(self, request: Request, call_next):
        request.state.client_ip = request.client.host
        request.state.user_agent = request.headers.get("user-agent", "")
        response = await call_next(request)
        return response
```

**Testing**:
- `Integration: create STIX object → audit_log entry with action='create', resource_type='stix_object'`
- `Integration: update STIX object confidence → audit_log entry with changes={"confidence": {"old": 60, "new": 85}}`
- `Integration: login attempt → audit_log entry with action='login' and client IP`
- `Integration: failed login → audit_log entry with action='login_failed'`
- `Integration: audit log entries are immutable — no UPDATE or DELETE allowed via API`
- `Unit: audit log query by user_id returns entries in reverse chronological order`

---

## Phase 3: STIX Object CRUD and Search

### Purpose

Implement the core intelligence object management: creating, reading, updating, searching, and correlating STIX 2.1 objects. After this phase, analysts can manually enter and query threat actors, indicators, campaigns, malware, and all other STIX SDOs and SCOs through the REST API. This is the "heart" of the TIP.

### Tasks

#### 3.1 — STIX object ingestion and validation

**What**: Implement STIX object create/update with validation against STIX 2.1 schema, deduplication by stix_id, and automatic extraction of indexed columns from JSONB payload.

**Design**:

```python
# src/tip/schemas/stix.py
from typing import Any

class StixObjectCreate(BaseModel):
    stix_data: dict[str, Any]  # full STIX 2.1 JSON object
    tlp_level: str | None = None  # override TLP if not in stix_data

class StixObjectUpdate(BaseModel):
    stix_data: dict[str, Any] | None = None
    confidence: int | None = None
    tlp_level: str | None = None
    is_revoked: bool | None = None

class StixObjectResponse(BaseModel):
    id: UUID
    stix_id: str
    stix_type: str
    object_class: str
    name: str | None
    confidence: int | None
    tlp_level: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    valid_from: datetime | None
    valid_until: datetime | None
    is_revoked: bool
    stix_data: dict[str, Any]
    created_at: datetime
    updated_at: datetime

class StixBundleImport(BaseModel):
    type: str = "bundle"
    id: str
    objects: list[dict[str, Any]]

class StixBundleImportResult(BaseModel):
    total: int
    created: int
    updated: int
    skipped: int
    errors: list[dict[str, str]]

# src/tip/services/stix_service.py
class StixService:
    STIX_SDO_TYPES = {
        "attack-pattern", "campaign", "course-of-action", "grouping",
        "identity", "indicator", "infrastructure", "intrusion-set",
        "location", "malware", "malware-analysis", "note", "observed-data",
        "opinion", "report", "threat-actor", "tool", "vulnerability",
    }
    STIX_SCO_TYPES = {
        "artifact", "autonomous-system", "directory", "domain-name",
        "email-addr", "email-message", "file", "ipv4-addr", "ipv6-addr",
        "mac-addr", "mutex", "network-traffic", "process", "software",
        "url", "user-account", "windows-registry-key", "x509-certificate",
    }

    def extract_indexed_fields(self, stix_data: dict) -> dict:
        """Extract searchable fields from STIX JSON into relational columns."""
        stix_type = stix_data["type"]
        fields = {
            "stix_id": stix_data["id"],
            "stix_type": stix_type,
            "spec_version": stix_data.get("spec_version", "2.1"),
            "object_class": self._classify(stix_type),
            "name": stix_data.get("name"),
            "description": stix_data.get("description"),
            "confidence": stix_data.get("confidence"),
            "stix_created": stix_data.get("created"),
            "stix_modified": stix_data.get("modified"),
            "first_seen": stix_data.get("first_seen"),
            "last_seen": stix_data.get("last_seen"),
            "valid_from": stix_data.get("valid_from"),
            "valid_until": stix_data.get("valid_until"),
            "pattern": stix_data.get("pattern"),
            "pattern_type": stix_data.get("pattern_type"),
            "is_revoked": stix_data.get("revoked", False),
        }
        # Extract observable value for SCOs
        if stix_type in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"):
            fields["observable_value"] = stix_data.get("value")
        elif stix_type == "file":
            hashes = stix_data.get("hashes", {})
            fields["observable_value"] = hashes.get("SHA-256") or hashes.get("MD5")
        return fields

    async def create_or_update(
        self, db: AsyncSession, stix_data: dict, org_id: UUID, feed_source_id: UUID | None = None
    ) -> tuple[StixObject, bool]:
        """Create or update STIX object. Returns (object, is_new)."""
        ...

    async def import_bundle(
        self, db: AsyncSession, bundle: StixBundleImport, org_id: UUID, feed_source_id: UUID | None = None
    ) -> StixBundleImportResult:
        """Import a STIX bundle with deduplication."""
        ...
```

API endpoints:
- `POST /api/v1/stix-objects` — create single STIX object
- `POST /api/v1/stix-objects/import` — import STIX bundle
- `GET /api/v1/stix-objects/{stix_id}` — get by STIX ID
- `PATCH /api/v1/stix-objects/{stix_id}` — update
- `DELETE /api/v1/stix-objects/{stix_id}` — soft-delete (set is_revoked=true)

**Testing**:
- `Unit: extract_indexed_fields for threat-actor → name, confidence, first_seen extracted`
- `Unit: extract_indexed_fields for indicator → pattern, pattern_type, valid_from extracted`
- `Unit: extract_indexed_fields for ipv4-addr → observable_value = IP address`
- `Unit: extract_indexed_fields for file with SHA-256 → observable_value = hash`
- `Unit: invalid STIX type → ValidationError`
- `Unit: missing required 'id' field in stix_data → ValidationError`
- `Integration: POST valid threat-actor → 201, JSONB stored, indexed fields extracted`
- `Integration: POST duplicate stix_id → existing object updated, not duplicated`
- `Integration: POST STIX bundle with 5 objects → StixBundleImportResult with created=5`
- `Integration: POST STIX bundle with 2 existing + 3 new → created=3, updated=2`
- `Integration: DELETE stix_id → is_revoked=true, object still queryable`
- `Integration: custom STIX extension properties preserved in stix_data JSONB`
- `Fixture: load test-bundle.json (10 objects) → all objects created with correct types`

---

#### 3.2 — STIX relationship and sighting management

**What**: Implement STIX Relationship Object (SRO) and Sighting CRUD with bidirectional traversal.

**Design**:

```python
# src/tip/schemas/stix.py
class RelationshipCreate(BaseModel):
    relationship_type: str  # 'uses', 'indicates', 'attributed-to', 'targets', etc.
    source_ref: str         # STIX ID
    target_ref: str         # STIX ID
    description: str | None = None
    confidence: int | None = None
    tlp_level: str | None = None
    start_time: datetime | None = None
    stop_time: datetime | None = None

class SightingCreate(BaseModel):
    sighting_of_ref: str    # STIX ID of the SDO being sighted
    where_sighted_refs: list[str] | None = None
    count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    description: str | None = None
    confidence: int | None = None

class RelationshipResponse(BaseModel):
    id: UUID
    stix_id: str
    relationship_type: str
    source_ref: str
    source_type: str
    target_ref: str
    target_type: str
    confidence: int | None
    start_time: datetime | None
    stop_time: datetime | None
    created_at: datetime
```

API endpoints:
- `POST /api/v1/relationships` — create relationship
- `GET /api/v1/relationships?source_ref=...&target_ref=...&type=...` — query relationships
- `GET /api/v1/stix-objects/{stix_id}/relationships` — all relationships for an object (both directions)
- `POST /api/v1/sightings` — record a sighting
- `GET /api/v1/stix-objects/{stix_id}/sightings` — sightings of an object

**Testing**:
- `Integration: create relationship between threat-actor and malware → source/target types auto-populated`
- `Integration: query relationships by source_ref → returns outgoing relationships`
- `Integration: query relationships for stix_id → returns both incoming and outgoing edges`
- `Integration: create sighting → count incremented, first_seen/last_seen recorded`
- `Integration: relationship with nonexistent source_ref → 404`
- `Integration: relationship with invalid relationship_type → 422`

---

#### 3.3 — Full-text search and filtering

**What**: Implement comprehensive search across all STIX objects with full-text, boolean, and faceted filtering.

**Design**:

```python
# src/tip/schemas/stix.py
class StixSearchQuery(BaseModel):
    q: str | None = None                        # full-text search query
    stix_types: list[str] | None = None         # filter by STIX type(s)
    object_class: str | None = None             # 'sdo', 'sco'
    tlp_levels: list[str] | None = None         # TLP filter
    confidence_min: int | None = None           # minimum confidence
    confidence_max: int | None = None
    first_seen_after: datetime | None = None
    first_seen_before: datetime | None = None
    valid_from_after: datetime | None = None
    valid_until_before: datetime | None = None
    pattern_type: str | None = None             # 'stix', 'sigma', 'yara', 'snort'
    observable_value: str | None = None         # exact IOC match
    is_revoked: bool | None = False
    is_expired: bool | None = False
    sort_by: str = "stix_modified"              # field to sort by
    sort_order: str = "desc"                    # 'asc' or 'desc'
    cursor: str | None = None                   # cursor-based pagination
    limit: int = 50

class StixSearchResult(BaseModel):
    items: list[StixObjectResponse]
    total: int
    next_cursor: str | None

# JSONB containment filters (advanced):
class StixJsonFilter(BaseModel):
    """Filter STIX objects by JSONB containment."""
    contains: dict | None = None  # e.g., {"threat_actor_types": ["nation-state"]}
```

API endpoints:
- `POST /api/v1/stix-objects/search` — advanced search with StixSearchQuery body
- `GET /api/v1/stix-objects?q=lazarus&stix_types=threat-actor&confidence_min=80` — simple search via query params
- `GET /api/v1/indicators/lookup?value=203.0.113.42` — fast IOC lookup

**Testing**:
- `Integration: search q="Lazarus Group" → returns threat actor with matching name`
- `Integration: search stix_types=["indicator","malware"] → returns only those types`
- `Integration: search confidence_min=80 → no objects with confidence < 80`
- `Integration: search with TLP filter → only matching TLP levels returned`
- `Integration: search observable_value="203.0.113.42" → returns matching IPv4 SCO`
- `Integration: search with JSONB containment {"threat_actor_types": ["nation-state"]} → matching actors only`
- `Integration: cursor-based pagination — two sequential queries return disjoint results`
- `Integration: full-text search for "ransomware financial" → results ranked by relevance`
- `Integration: IOC lookup for nonexistent IP → empty result, 200 (not 404)`
- `Unit: search with invalid sort_by field → 422`

---

#### 3.4 — STIX bundle export

**What**: Export STIX objects as STIX 2.1 bundles for sharing via TAXII or manual download.

**Design**:

```python
# src/tip/services/stix_service.py
class StixService:
    async def export_bundle(
        self,
        db: AsyncSession,
        org_id: UUID,
        stix_ids: list[str] | None = None,
        stix_types: list[str] | None = None,
        tlp_max: str | None = None,           # export only up to this TLP level
        modified_after: datetime | None = None,
        include_relationships: bool = True,
    ) -> dict:
        """Export matching objects as a STIX 2.1 bundle."""
        # Returns:
        # {
        #   "type": "bundle",
        #   "id": "bundle--<uuid>",
        #   "objects": [<stix_data from each matching stix_object>]
        # }
```

TLP sharing enforcement order: `TLP:CLEAR < TLP:GREEN < TLP:AMBER < TLP:AMBER+STRICT < TLP:RED`

API endpoints:
- `POST /api/v1/stix-objects/export` — export bundle matching filter criteria
- `GET /api/v1/stix-objects/export?modified_after=2026-05-01&tlp_max=TLP:GREEN` — export via query params

**Testing**:
- `Integration: export with no filters → bundle containing all non-revoked objects`
- `Integration: export with tlp_max=TLP:GREEN → no TLP:AMBER or TLP:RED objects`
- `Integration: export with include_relationships=true → relationships between exported objects included`
- `Integration: export with modified_after → only recently modified objects`
- `Unit: exported bundle validates against STIX 2.1 schema (using python-stix2 parse)`
- `Fixture: round-trip test — import bundle, export same objects, compare JSON equality`

---

## Phase 4: Feed Ingestion Engine

### Purpose

Implement the multi-source feed polling and ingestion pipeline. After this phase, the platform automatically ingests indicators from TAXII 2.1 servers, MISP instances, STIX bundle files, and CSV files on configurable schedules with deduplication and normalization.

### Tasks

#### 4.1 — Feed source management

**What**: Implement feed source CRUD with configuration for authentication, polling schedule, and object filtering.

**Design**:

```python
# src/tip/schemas/feed.py
class FeedSourceCreate(BaseModel):
    name: str
    description: str | None = None
    source_type: str  # 'taxii', 'misp', 'stix_bundle', 'csv', 'api'
    url: str | None = None
    auth_config: dict | None = None
    # Example auth_config for TAXII:
    # {"type": "api_key", "header": "Authorization", "value": "Bearer <token>"}
    # Example auth_config for MISP:
    # {"type": "api_key", "header": "Authorization", "value": "<misp-auth-key>"}
    polling_config: dict = {
        "interval_minutes": 60,
        "max_objects_per_poll": 10000,
        "deduplicate": True,
    }
    filter_config: dict = {}
    # Example filter_config:
    # {"stix_types": ["indicator", "malware"], "min_confidence": 50, "tlp_max": "TLP:AMBER"}

class FeedSourceResponse(BaseModel):
    id: UUID
    name: str
    source_type: str
    url: str | None
    is_active: bool
    last_poll_at: datetime | None
    last_poll_status: str | None
    stats: dict
    created_at: datetime

class FeedIngestionLogResponse(BaseModel):
    id: UUID
    feed_source_id: UUID
    started_at: datetime
    completed_at: datetime | None
    status: str
    stats: dict  # {"received": 500, "created": 120, "updated": 350, "skipped": 30}
```

API endpoints:
- `POST /api/v1/feeds` — create feed source
- `GET /api/v1/feeds` — list feed sources
- `PATCH /api/v1/feeds/{id}` — update feed configuration
- `DELETE /api/v1/feeds/{id}` — deactivate feed
- `POST /api/v1/feeds/{id}/poll` — trigger immediate poll
- `GET /api/v1/feeds/{id}/logs` — ingestion history

**Testing**:
- `Integration: create TAXII feed source → stored with encrypted auth config`
- `Integration: update polling interval → scheduler picks up new interval`
- `Integration: deactivate feed → polling stops`
- `Integration: trigger manual poll → ingestion runs immediately`
- `Integration: ingestion logs show received/created/updated/skipped counts`

---

#### 4.2 — Abstract ingester interface and TAXII 2.1 client

**What**: Implement the feed ingester abstraction and the TAXII 2.1 client ingester using taxii2-client.

**Design**:

```python
# src/tip/ingestion/base.py
from abc import ABC, abstractmethod

@dataclass
class IngestionResult:
    received: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[dict] = field(default_factory=list)

class BaseIngester(ABC):
    def __init__(self, feed_source: FeedSource, db: AsyncSession, org_id: UUID): ...

    @abstractmethod
    async def poll(self) -> IngestionResult:
        """Poll the feed and ingest new objects."""
        ...

# src/tip/ingestion/taxii_ingester.py
class TaxiiIngester(BaseIngester):
    """Ingest STIX objects from a TAXII 2.1 server."""

    async def poll(self) -> IngestionResult:
        # 1. Connect to TAXII server using taxii2-client
        # 2. Discover collections
        # 3. For each collection, get objects added since last_poll_at
        # 4. Parse STIX bundles
        # 5. Deduplicate by stix_id (skip if stix_modified <= existing)
        # 6. Call stix_service.create_or_update for each object
        # 7. Return IngestionResult
        ...
```

**Testing**:
- `Integration (mocked): TAXII server returns 3 new indicators → IngestionResult.created == 3`
- `Integration (mocked): TAXII server returns duplicate stix_id with older modified → skipped`
- `Integration (mocked): TAXII server returns duplicate stix_id with newer modified → updated`
- `Integration (mocked): TAXII server returns 401 → IngestionResult records auth error`
- `Integration (mocked): TAXII server returns empty collection → received=0, no errors`
- `Unit: TAXII polling respects last_poll_at — sends added_after parameter`

---

#### 4.3 — MISP feed ingester

**What**: Implement MISP feed ingestion using PyMISP, mapping MISP events/attributes to STIX 2.1 objects.

**Design**:

```python
# src/tip/ingestion/misp_ingester.py
class MispIngester(BaseIngester):
    """Ingest from MISP instances via PyMISP."""

    MISP_TO_STIX_TYPE_MAP = {
        "ip-src": "ipv4-addr",
        "ip-dst": "ipv4-addr",
        "domain": "domain-name",
        "hostname": "domain-name",
        "url": "url",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
        "email-src": "email-addr",
        "email-dst": "email-addr",
        "filename": "file",
    }

    def misp_attribute_to_stix(self, attr: dict) -> dict | None:
        """Convert a MISP attribute to a STIX 2.1 indicator."""
        ...

    def misp_event_to_stix_bundle(self, event: dict) -> list[dict]:
        """Convert a MISP event (with attributes) to STIX objects."""
        ...
```

**Testing**:
- `Unit: MISP ip-src attribute → STIX ipv4-addr indicator with correct pattern`
- `Unit: MISP sha256 attribute → STIX file indicator with SHA-256 hash`
- `Unit: MISP event with TLP:GREEN tag → indicators have tlp_level=TLP:GREEN`
- `Unit: MISP attribute with unsupported type → returns None (skipped)`
- `Integration (mocked): poll MISP instance → events converted and ingested`
- `Fixture: misp-event.json → correct STIX bundle output`

---

#### 4.4 — CSV and STIX bundle file ingesters

**What**: Implement ingestion from CSV files (bulk IOC import) and static STIX bundle files.

**Design**:

```python
# src/tip/ingestion/csv_ingester.py
class CsvIngester(BaseIngester):
    """Import indicators from CSV files."""
    # Expected columns: type, value, confidence, tlp, description, tags
    # type values: ip, domain, url, hash-md5, hash-sha256, email

# src/tip/ingestion/stix_bundle_ingester.py
class StixBundleIngester(BaseIngester):
    """Import from STIX 2.1 bundle JSON files."""
    # Validates bundle structure, then delegates to stix_service.import_bundle
```

API endpoints:
- `POST /api/v1/feeds/upload/csv` — upload CSV file for bulk import
- `POST /api/v1/feeds/upload/stix-bundle` — upload STIX bundle JSON file

**Testing**:
- `Integration: upload CSV with 100 IP indicators → 100 STIX ipv4-addr objects created`
- `Integration: upload CSV with invalid row → error recorded, valid rows still imported`
- `Integration: upload STIX bundle JSON → objects created via stix_service`
- `Fixture: sample.csv and sample-bundle.json committed to tests/fixtures/`

---

#### 4.5 — Scheduled feed polling with Celery Beat

**What**: Configure Celery Beat to poll active feeds on their configured schedules.

**Design**:

```python
# src/tip/workers/feed_tasks.py
from celery import shared_task

@shared_task(bind=True, max_retries=3, default_retry_delay=300)
def poll_feed(self, feed_source_id: str) -> dict:
    """Poll a single feed source and ingest results."""
    ...

@shared_task
def poll_all_active_feeds() -> dict:
    """Discover all active feeds due for polling and dispatch individual poll tasks."""
    ...

# src/tip/workers/scheduler.py
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    "poll-all-feeds-every-5-minutes": {
        "task": "src.tip.workers.feed_tasks.poll_all_active_feeds",
        "schedule": crontab(minute="*/5"),
    },
    "expire-indicators-daily": {
        "task": "src.tip.workers.maintenance_tasks.expire_indicators",
        "schedule": crontab(hour=2, minute=0),  # 2:00 AM daily
    },
}
```

**Testing**:
- `Integration: Celery Beat dispatches poll_all_active_feeds on schedule`
- `Integration: poll_all_active_feeds finds 3 active feeds → dispatches 3 poll_feed tasks`
- `Integration: feed with polling_interval=120 minutes polled 10 minutes ago → skipped (not due)`
- `Integration: poll_feed fails → retried up to 3 times with 300s delay`
- `Integration: poll_feed records IngestionResult in feed_ingestion_log`
- `Integration: feed last_poll_at and last_poll_status updated after poll`

---

## Phase 5: TAXII 2.1 Server

### Purpose

Implement a TAXII 2.1 compliant server that allows external systems (SIEMs, ISACs, other TIPs) to discover, subscribe to, and consume threat intelligence collections. This phase makes the platform a first-class participant in the STIX/TAXII sharing ecosystem per OASIS TAXII 2.1 specification.

### Tasks

#### 5.1 — TAXII discovery and API root endpoints

**What**: Implement TAXII 2.1 discovery and API root endpoints per the OASIS specification.

**Design**:

```python
# src/tip/schemas/taxii.py
class TaxiiDiscovery(BaseModel):
    title: str
    description: str | None = None
    contact: str | None = None
    default: str  # URL of default API root
    api_roots: list[str]

class TaxiiApiRoot(BaseModel):
    title: str
    description: str | None = None
    versions: list[str] = ["application/taxii+json;version=2.1"]
    max_content_length: int = 10485760  # 10 MB

# TAXII endpoints (per OASIS TAXII 2.1 spec):
# GET  /taxii/2.1/                    → TaxiiDiscovery
# GET  /taxii/2.1/{api-root}/         → TaxiiApiRoot
# GET  /taxii/2.1/{api-root}/status/{status-id} → TaxiiStatus (for async operations)

# Content-Type: application/taxii+json;version=2.1
```

**Testing**:
- `Integration: GET /taxii/2.1/ → 200 with correct TaxiiDiscovery response`
- `Integration: GET /taxii/2.1/ with Accept: application/taxii+json;version=2.1 → correct content-type`
- `Integration: GET /taxii/2.1/ without auth → 401`
- `Integration: GET /taxii/2.1/default/ → 200 with TaxiiApiRoot`

---

#### 5.2 — TAXII collection discovery and object retrieval

**What**: Implement TAXII 2.1 collection listing and STIX object retrieval with filtering and pagination.

**Design**:

```python
# TAXII Collection endpoints:
# GET  /taxii/2.1/{api-root}/collections/                    → list collections
# GET  /taxii/2.1/{api-root}/collections/{collection-id}/    → collection details
# GET  /taxii/2.1/{api-root}/collections/{collection-id}/objects/  → get objects
# POST /taxii/2.1/{api-root}/collections/{collection-id}/objects/  → add objects

# TAXII filtering parameters (per spec):
# ?added_after=2026-05-01T00:00:00Z
# ?match[type]=indicator,malware
# ?match[id]=indicator--<uuid>
# ?match[version]=all|first|last
# ?limit=100

class TaxiiEnvelope(BaseModel):
    more: bool = False
    objects: list[dict]  # raw STIX JSON objects from stix_data column

class TaxiiCollection(BaseModel):
    id: str
    title: str
    description: str | None = None
    can_read: bool
    can_write: bool
    media_types: list[str] = ["application/stix+json;version=2.1"]
```

**Testing**:
- `Integration: GET /collections/ → list of collections for authenticated user's organization`
- `Integration: GET /collections/{id}/objects/ → TaxiiEnvelope with STIX objects`
- `Integration: GET /collections/{id}/objects/?added_after=... → only newer objects`
- `Integration: GET /collections/{id}/objects/?match[type]=indicator → only indicators`
- `Integration: POST /collections/{id}/objects/ with STIX bundle → objects ingested`
- `Integration: POST to read-only collection → 403`
- `Integration: pagination — first request returns more=true, follow-up returns remaining objects`

---

## Phase 6: MITRE ATT&CK Integration and Detection Rule Export

### Purpose

Integrate MITRE ATT&CK as an enrichment vocabulary: ingest the ATT&CK STIX dataset, map indicators and threat actors to techniques/tactics, and export detection rules in YARA, Sigma, and Snort formats. After this phase, analysts can correlate intelligence with the ATT&CK framework and generate defensive artefacts with one click.

### Tasks

#### 6.1 — MITRE ATT&CK dataset ingestion

**What**: Ingest the MITRE ATT&CK Enterprise dataset from the official STIX 2.1 data repository into the platform as STIX objects.

**Design**:

```python
# src/tip/services/attack_service.py
class AttackService:
    ATTACK_STIX_DATA_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

    async def sync_attack_data(self, db: AsyncSession, org_id: UUID) -> dict:
        """Download and ingest the latest ATT&CK dataset.
        Returns: {"tactics": N, "techniques": N, "sub_techniques": N, "mitigations": N}
        """
        ...

    async def get_techniques_for_object(
        self, db: AsyncSession, stix_id: str
    ) -> list[StixObjectResponse]:
        """Find ATT&CK techniques related to a STIX object via relationships."""
        ...

    async def get_attack_navigator_data(
        self, db: AsyncSession, stix_ids: list[str]
    ) -> dict:
        """Generate ATT&CK Navigator layer JSON for a set of STIX objects."""
        # Returns a Navigator layer JSON:
        # {
        #   "name": "Coverage for <query>",
        #   "versions": {"attack": "16", "navigator": "5.1", "layer": "4.5"},
        #   "domain": "enterprise-attack",
        #   "techniques": [
        #     {"techniqueID": "T1566.001", "score": 85, "color": "#ff6666"},
        #     ...
        #   ]
        # }
```

API endpoints:
- `POST /api/v1/attack/sync` — trigger ATT&CK data sync (admin only)
- `GET /api/v1/stix-objects/{stix_id}/attack-techniques` — ATT&CK techniques for an object
- `POST /api/v1/attack/navigator-layer` — generate Navigator layer for selected objects

**Testing**:
- `Integration (mocked): sync ATT&CK → tactics, techniques, relationships created as STIX objects`
- `Integration: query techniques for threat actor with known ATT&CK mappings → correct techniques returned`
- `Integration: generate Navigator layer → valid ATT&CK Navigator JSON with technique scores`
- `Unit: ATT&CK data maps correctly to STIX attack-pattern objects`

---

#### 6.2 — Detection rule CRUD and generation

**What**: Implement detection rule management with manual creation and template-based generation from indicators.

**Design**:

```python
# src/tip/schemas/detection.py
class DetectionRuleCreate(BaseModel):
    name: str
    description: str | None = None
    rule_type: str  # 'yara', 'sigma', 'snort', 'suricata'
    rule_content: str
    severity: str | None = None  # 'low', 'medium', 'high', 'critical'
    source_stix_ids: list[str] = []

class DetectionRuleResponse(BaseModel):
    id: UUID
    name: str
    rule_type: str
    rule_content: str
    version: int
    severity: str | None
    is_ai_generated: bool
    source_stix_ids: list[str]
    metadata: dict
    created_at: datetime

# src/tip/services/detection_service.py
class DetectionService:
    def generate_sigma_from_indicator(self, indicator: StixObject) -> str:
        """Generate a Sigma rule from a STIX indicator."""
        # Maps STIX pattern types to Sigma rule templates
        ...

    def generate_yara_from_indicator(self, indicator: StixObject) -> str:
        """Generate a YARA rule from a STIX indicator (file-based IOCs)."""
        ...

    def generate_snort_from_indicator(self, indicator: StixObject) -> str:
        """Generate a Snort rule from a STIX indicator (network IOCs)."""
        ...

    async def export_rules(
        self, db: AsyncSession, rule_type: str, org_id: UUID
    ) -> str:
        """Export all rules of a type as a single file."""
        ...
```

API endpoints:
- `POST /api/v1/detection-rules` — create rule manually
- `GET /api/v1/detection-rules` — list rules with filtering
- `POST /api/v1/detection-rules/generate` — generate rule from indicator(s)
- `GET /api/v1/detection-rules/export/{rule_type}` — export all rules of a type as downloadable file

**Testing**:
- `Unit: generate_sigma_from_indicator with ipv4-addr pattern → valid Sigma YAML`
- `Unit: generate_sigma_from_indicator with domain-name pattern → valid Sigma YAML`
- `Unit: generate_yara_from_indicator with file hash → valid YARA rule`
- `Unit: generate_snort_from_indicator with IP pattern → valid Snort rule`
- `Integration: POST generate from indicator → rule created with is_ai_generated=false`
- `Integration: export sigma rules → concatenated YAML file`
- `Integration: export yara rules → concatenated YARA file`
- `Fixture: expected-sigma-output.yml for known indicator patterns`

---

## Phase 7: AI Enrichment Pipeline

### Purpose

Implement the AI-native features that differentiate this platform: LLM-powered IOC extraction from unstructured text, confidence scoring, and detection rule generation. After this phase, analysts can paste threat reports and have IOCs automatically extracted, and the system can auto-generate detection rules from ingested intelligence.

### Tasks

#### 7.1 — LLM provider abstraction

**What**: Create a provider-agnostic LLM interface supporting Anthropic Claude and OpenAI-compatible APIs.

**Design**:

```python
# src/tip/ai/provider.py
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class LLMResponse:
    content: str
    model: str
    input_tokens: int
    output_tokens: int
    stop_reason: str

class LLMProvider(ABC):
    @abstractmethod
    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        response_format: dict | None = None,  # for JSON mode
    ) -> LLMResponse: ...

class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = model

    async def complete(self, system_prompt, user_prompt, **kwargs) -> LLMResponse:
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=kwargs.get("max_tokens", 4096),
            temperature=kwargs.get("temperature", 0.0),
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return LLMResponse(
            content=response.content[0].text,
            model=self.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            stop_reason=response.stop_reason,
        )

class OpenAIProvider(LLMProvider):
    """OpenAI-compatible provider (supports OpenAI, Azure OpenAI, local models)."""
    ...

def get_llm_provider(settings: Settings) -> LLMProvider:
    if settings.llm_provider == "anthropic":
        return AnthropicProvider(api_key=settings.anthropic_api_key.get_secret_value())
    elif settings.llm_provider == "openai":
        return OpenAIProvider(api_key=settings.openai_api_key.get_secret_value())
    raise ValueError(f"Unknown LLM provider: {settings.llm_provider}")
```

**Testing**:
- `Unit (mocked): AnthropicProvider.complete → LLMResponse with correct fields`
- `Unit (mocked): OpenAIProvider.complete → LLMResponse with correct fields`
- `Unit: get_llm_provider("anthropic") → AnthropicProvider instance`
- `Unit: get_llm_provider("invalid") → ValueError`

---

#### 7.2 — Automated IOC extraction from unstructured text

**What**: Use LLMs to parse threat reports, blog posts, and raw text to extract and normalise indicators into STIX objects.

**Design**:

```python
# src/tip/ai/ioc_extractor.py
class IOCExtractor:
    async def extract_from_text(
        self, text: str, source_url: str | None = None
    ) -> list[dict]:
        """Extract IOCs from unstructured text, return as STIX objects."""
        ...

    async def extract_from_url(self, url: str) -> list[dict]:
        """Fetch URL content and extract IOCs."""
        ...

# src/tip/ai/prompts/ioc_extraction.py
IOC_EXTRACTION_SYSTEM_PROMPT = """You are a cyber threat intelligence analyst.
Extract ALL indicators of compromise (IOCs) from the provided text.

For each IOC, output a JSON object with:
- "type": one of "ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "file"
- "value": the extracted value
- "context": brief description of how this IOC appears in the text
- "confidence": 0-100 confidence that this is a genuine IOC (not a benign reference)
- "hashes": (for file type only) {"MD5": "...", "SHA-1": "...", "SHA-256": "..."}

Rules:
- Defang IOCs (e.g., "hxxps://", "1.2.3[.]4") must be refanged before output
- Exclude private/reserved IP ranges (10.x, 172.16-31.x, 192.168.x) unless clearly malicious
- Exclude common benign domains (google.com, microsoft.com) unless clearly IOC context
- Output ONLY valid JSON array. No markdown, no explanation.
"""

IOC_EXTRACTION_USER_PROMPT = """Extract all IOCs from the following threat report:

---
{text}
---

Return a JSON array of IOC objects."""
```

API endpoints:
- `POST /api/v1/enrichment/extract-iocs` — extract IOCs from text/URL
- `GET /api/v1/enrichment/jobs/{id}` — check job status and results

**Testing**:
- `Unit (mocked LLM): text with 3 IPs and 2 domains → 5 STIX indicator objects`
- `Unit (mocked LLM): text with defanged IP "1.2.3[.]4" → refanged to "1.2.3.4"`
- `Unit (mocked LLM): text with private IP 192.168.1.1 → excluded from results`
- `Unit (mocked LLM): text with SHA-256 hash → file indicator with hash`
- `Integration: POST extract-iocs with report text → enrichment job created, STIX objects stored`
- `Integration: POST extract-iocs with URL → text fetched, IOCs extracted`
- `Fixture: sample-threat-report.txt with known IOCs → verify all expected IOCs extracted`

---

#### 7.3 — AI confidence scoring

**What**: Use LLMs to assess and adjust indicator confidence scores based on source reliability, corroboration, and context.

**Design**:

```python
# src/tip/ai/confidence_scorer.py
class ConfidenceScorer:
    async def score_indicator(
        self, indicator: dict, context: dict
    ) -> dict:
        """Assess indicator confidence based on context.
        Returns: {"confidence": 85, "reasoning": "...", "factors": {...}}
        """
        ...

    async def batch_score(
        self, indicators: list[dict], context: dict
    ) -> list[dict]:
        """Score multiple indicators in a single LLM call for efficiency."""
        ...

# Context dict includes:
# - source_type: "feed", "analyst", "ai_extracted"
# - source_reputation: 0-100
# - corroboration_count: how many feeds report this IOC
# - age_days: how old the indicator is
# - sighting_count: how many times sighted in environment
```

**Testing**:
- `Unit (mocked LLM): indicator from high-reputation feed with 3 corroborations → confidence >= 80`
- `Unit (mocked LLM): indicator from unknown source with no corroboration → confidence <= 50`
- `Unit (mocked LLM): batch_score with 5 indicators → 5 scored results`
- `Integration: score indicator → confidence updated in stix_object, audit log entry created`

---

#### 7.4 — AI detection rule generation

**What**: Use LLMs to automatically generate Sigma, YARA, and Snort rules from threat intelligence.

**Design**:

```python
# src/tip/ai/rule_generator.py
class AIRuleGenerator:
    async def generate_sigma_rule(
        self, indicator: dict, attack_techniques: list[str]
    ) -> str:
        """Generate a Sigma detection rule from an indicator and ATT&CK context."""
        ...

    async def generate_yara_rule(
        self, malware: dict, file_indicators: list[dict]
    ) -> str:
        """Generate a YARA rule from malware analysis data and file indicators."""
        ...

# src/tip/ai/prompts/rule_generation.py
SIGMA_GENERATION_PROMPT = """You are a detection engineer.
Generate a Sigma detection rule for the following threat indicator.

Indicator: {indicator_json}
ATT&CK Techniques: {techniques}

Requirements:
- Valid Sigma 2.0 YAML syntax
- Include appropriate logsource (category, product, service)
- Set level to match indicator confidence (high confidence = high level)
- Include falsepositives section
- Reference the indicator's STIX ID in the rule's references
"""
```

API endpoints:
- `POST /api/v1/enrichment/generate-rules` — generate detection rules from indicators
- Body: `{"indicator_stix_ids": [...], "rule_types": ["sigma", "yara"]}`

**Testing**:
- `Unit (mocked LLM): IP indicator + T1566 → valid Sigma YAML with network logsource`
- `Unit (mocked LLM): file hash indicator → valid YARA rule with hash strings`
- `Integration: generate rules → detection_rule entries created with is_ai_generated=true`
- `Integration: generated Sigma rule validates against Sigma schema`

---

## Phase 8: Frontend — Dashboard and Analyst Interface

### Purpose

Build the React frontend providing the analyst workflow: STIX object browsing, search, graph visualisation, MITRE ATT&CK navigator, and detection rule management. After this phase, analysts have a modern web interface for all TIP operations.

### Tasks

#### 8.1 — Frontend scaffolding and API client

**What**: Initialize the React + TypeScript + Vite project, configure routing, authentication, and auto-generate the API client from the OpenAPI spec.

**Design**:

```typescript
// src/frontend/src/types/stix.ts
interface StixObject {
  id: string;
  stix_id: string;
  stix_type: string;
  object_class: "sdo" | "sco" | "smo";
  name: string | null;
  confidence: number | null;
  tlp_level: string | null;
  first_seen: string | null;
  last_seen: string | null;
  valid_from: string | null;
  valid_until: string | null;
  is_revoked: boolean;
  stix_data: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface StixRelationship {
  id: string;
  stix_id: string;
  relationship_type: string;
  source_ref: string;
  source_type: string;
  target_ref: string;
  target_type: string;
  confidence: number | null;
}

interface SearchQuery {
  q?: string;
  stix_types?: string[];
  tlp_levels?: string[];
  confidence_min?: number;
  sort_by?: string;
  sort_order?: "asc" | "desc";
  cursor?: string;
  limit?: number;
}

interface SearchResult {
  items: StixObject[];
  total: number;
  next_cursor: string | null;
}
```

Routes:
```
/                     → Dashboard
/login                → Login page
/search               → STIX object search
/objects/:stixId      → Object detail view
/threat-actors        → Threat actor list
/indicators           → Indicator list
/campaigns            → Campaign list
/feeds                → Feed management
/detection-rules      → Detection rule management
/attack-navigator     → ATT&CK navigator view
/enrichment           → AI enrichment tools
/workspaces           → Collaboration workspaces
/admin                → Organization/user management
```

**Testing**:
- `Unit: Vite build completes without errors`
- `Unit: API client types match OpenAPI spec`
- `E2E: unauthenticated user → redirected to /login`
- `E2E: successful login → redirected to dashboard`

---

#### 8.2 — Search interface and STIX object browser

**What**: Build the search UI with faceted filtering, result list, and object detail views.

**Design**:

Components:
- `SearchBar` — text input with type-ahead suggestions
- `SearchFilters` — faceted filter panel (STIX type, TLP, confidence range, date range)
- `SearchResults` — paginated result list with STIX type icons, confidence badges, TLP indicators
- `StixObjectDetail` — full object view with raw JSON, relationships, sightings, timeline
- `TLPBadge` — colour-coded TLP indicator component
- `ConfidenceMeter` — visual confidence score display

```typescript
// src/frontend/src/components/search/SearchFilters.tsx
interface SearchFilterState {
  stixTypes: string[];
  tlpLevels: string[];
  confidenceRange: [number, number];
  dateRange: { from: string | null; to: string | null };
  patternType: string | null;
  isRevoked: boolean;
}
```

**Testing**:
- `E2E: type "Lazarus" in search → results list shows matching threat actors`
- `E2E: filter by stix_type=indicator → only indicators in results`
- `E2E: filter by confidence >= 80 → no low-confidence results`
- `E2E: click result → navigates to object detail view`
- `E2E: object detail shows relationships tab with linked objects`
- `Unit: TLPBadge renders correct colour for each TLP level`
- `Unit: ConfidenceMeter renders correct percentage fill`

---

#### 8.3 — Knowledge graph visualisation

**What**: Build an interactive graph visualisation using Cytoscape.js showing STIX object relationships.

**Design**:

```typescript
// src/frontend/src/components/graph/ThreatGraph.tsx
interface GraphNode {
  id: string;         // stix_id
  label: string;      // name
  type: string;       // stix_type
  confidence: number;
  tlp: string;
}

interface GraphEdge {
  id: string;
  source: string;     // source stix_id
  target: string;     // target stix_id
  label: string;      // relationship_type
  confidence: number;
}

// Node styling by STIX type:
const NODE_STYLES: Record<string, { color: string; shape: string }> = {
  "threat-actor": { color: "#e74c3c", shape: "diamond" },
  "malware": { color: "#e67e22", shape: "pentagon" },
  "indicator": { color: "#3498db", shape: "ellipse" },
  "campaign": { color: "#9b59b6", shape: "hexagon" },
  "vulnerability": { color: "#f39c12", shape: "triangle" },
  "attack-pattern": { color: "#1abc9c", shape: "round-rectangle" },
  "tool": { color: "#95a5a6", shape: "rectangle" },
  "infrastructure": { color: "#34495e", shape: "octagon" },
};
```

Features:
- Click node to show detail panel
- Expand node to load connected objects (1-hop)
- Filter displayed relationship types
- Layout algorithms: force-directed (default), hierarchical, circular
- Export graph as PNG/SVG

**Testing**:
- `E2E: navigate to threat actor detail → graph tab shows connected nodes`
- `E2E: click expand on malware node → loads connected attack patterns`
- `E2E: filter to "uses" relationships → only "uses" edges displayed`
- `Unit: NODE_STYLES maps all STIX SDO types`

---

#### 8.4 — MITRE ATT&CK Navigator view

**What**: Render the MITRE ATT&CK matrix with heat-mapping based on intelligence coverage.

**Design**:

The navigator view renders the ATT&CK Enterprise matrix as a grid of tactics (columns) and techniques (rows), with colour intensity reflecting the number of correlated intelligence objects. Uses the ATT&CK Navigator layer JSON from the API (Phase 6.1).

```typescript
// src/frontend/src/components/attack/AttackNavigator.tsx
interface NavigatorLayer {
  name: string;
  domain: string;
  techniques: Array<{
    techniqueID: string;   // e.g., "T1566.001"
    score: number;         // 0-100
    color: string;
    comment: string;
    metadata: Array<{ name: string; value: string }>;
  }>;
}
```

**Testing**:
- `E2E: navigate to ATT&CK navigator → matrix renders with correct tactic columns`
- `E2E: techniques with linked intelligence show colour highlighting`
- `E2E: click technique cell → shows linked indicators and threat actors`
- `E2E: export Navigator layer as JSON → valid ATT&CK Navigator format`

---

#### 8.5 — Dashboard and statistics

**What**: Build the main dashboard with key threat intelligence metrics, recent activity, and feed status.

**Design**:

Dashboard widgets:
- **Intelligence Summary** — total objects by type (threat actors, indicators, campaigns, etc.)
- **Feed Health** — active feeds, last poll status, error rates
- **Recent Activity** — timeline of recently created/updated objects
- **Indicator Confidence Distribution** — histogram of confidence scores
- **TLP Distribution** — pie chart of objects by TLP level
- **Top Threat Actors** — most connected/active threat actors
- **Expiring Indicators** — indicators approaching valid_until date

API endpoint for dashboard data:
- `GET /api/v1/dashboard/summary` — aggregated statistics

**Testing**:
- `E2E: dashboard loads with all widgets populated`
- `E2E: feed health widget shows correct status for each feed`
- `E2E: clicking a dashboard item navigates to the relevant detail view`

---

## Phase 9: Analyst Collaboration Workspaces

### Purpose

Implement shared investigation workspaces where analyst teams can collaborate on threat investigations, draft finished intelligence reports, and conduct peer review. After this phase, analyst teams can work together on complex investigations with shared context.

### Tasks

#### 9.1 — Workspace CRUD and membership

**What**: Implement workspace lifecycle management with role-based membership.

**Design**:

```python
# src/tip/schemas/workspace.py
class WorkspaceCreate(BaseModel):
    name: str
    description: str | None = None
    workspace_type: str  # 'investigation', 'report_draft', 'hunt'
    stix_object_refs: list[str] = []  # initial STIX objects to include

class WorkspaceResponse(BaseModel):
    id: UUID
    name: str
    workspace_type: str
    status: str  # 'active', 'archived', 'completed'
    stix_object_refs: list[str]
    members: list[WorkspaceMemberResponse]
    created_at: datetime

class WorkspaceMemberResponse(BaseModel):
    user_id: UUID
    display_name: str
    role: str  # 'owner', 'contributor', 'viewer'
    joined_at: datetime
```

API endpoints:
- `POST /api/v1/workspaces` — create workspace
- `GET /api/v1/workspaces` — list user's workspaces
- `PATCH /api/v1/workspaces/{id}` — update workspace
- `POST /api/v1/workspaces/{id}/members` — add member
- `POST /api/v1/workspaces/{id}/stix-objects` — add STIX object to workspace

**Testing**:
- `Integration: create workspace → owner automatically added as member`
- `Integration: add member with 'contributor' role → member can add STIX objects`
- `Integration: viewer cannot modify workspace`
- `Integration: add STIX object to workspace → appears in stix_object_refs`
- `Integration: archive workspace → status changes, workspace read-only`

---

#### 9.2 — Workspace comments and discussion

**What**: Implement threaded commenting on workspaces and individual STIX objects within workspaces.

**Design**:

```python
class CommentCreate(BaseModel):
    content: str
    parent_id: UUID | None = None  # for threaded replies
    stix_ref: str | None = None    # comment on specific STIX object in workspace

class CommentResponse(BaseModel):
    id: UUID
    workspace_id: UUID
    user_id: UUID
    display_name: str
    content: str
    parent_id: UUID | None
    stix_ref: str | None
    created_at: datetime
    replies: list["CommentResponse"] = []
```

API endpoints:
- `POST /api/v1/workspaces/{id}/comments` — add comment
- `GET /api/v1/workspaces/{id}/comments` — list comments (threaded)

**Testing**:
- `Integration: add comment → comment stored with workspace_id and user_id`
- `Integration: reply to comment → parent_id set, appears nested in GET response`
- `Integration: comment on specific STIX object → stix_ref set`
- `Integration: non-member cannot comment → 403`

---

## Phase 10: Conversational Query Interface

### Purpose

Implement the natural-language query interface that lets analysts query the intelligence corpus conversationally (e.g., "Show me all TTPs used by Lazarus Group targeting financial institutions in the past 90 days"). This is a key AI-native differentiator identified in the research.

### Tasks

#### 10.1 — Natural language to structured query translation

**What**: Use LLMs to translate natural language threat intelligence questions into structured search queries against the STIX object store.

**Design**:

```python
# src/tip/ai/query_translator.py
class QueryTranslator:
    async def translate(self, natural_query: str) -> StixSearchQuery:
        """Convert natural language question to StixSearchQuery."""
        ...

    async def execute_and_summarise(
        self, natural_query: str, db: AsyncSession, org_id: UUID
    ) -> dict:
        """Translate query, execute search, and generate natural language summary.
        Returns: {
            "query": <StixSearchQuery used>,
            "results": [<StixObjectResponse>, ...],
            "summary": "Found 12 indicators linked to Lazarus Group...",
            "follow_up_suggestions": ["Show related campaigns", "Export as STIX bundle"]
        }
        """
        ...

# System prompt for query translation:
QUERY_TRANSLATION_PROMPT = """You are a threat intelligence query translator.
Convert the user's natural language question into a structured search query.

Available search fields:
- q: full-text search query
- stix_types: list of STIX types (threat-actor, indicator, malware, campaign, etc.)
- confidence_min: minimum confidence score (0-100)
- first_seen_after / first_seen_before: date range
- valid_from_after / valid_until_before: indicator validity range
- tlp_levels: TLP levels to include
- observable_value: exact IOC value match

Output a JSON object matching the StixSearchQuery schema.
If the question implies relationships (e.g., "TTPs used by X"), also output:
- relationship_query: {"source_type": "...", "relationship_type": "...", "target_type": "..."}
"""
```

API endpoint:
- `POST /api/v1/query` — natural language query
  - Request: `{"query": "Show me all TTPs used by Lazarus Group targeting financial institutions in the past 90 days"}`
  - Response: `{"query": {...}, "results": [...], "summary": "...", "follow_up_suggestions": [...]}`

**Testing**:
- `Unit (mocked LLM): "Show indicators for Lazarus Group" → StixSearchQuery with q="Lazarus Group", stix_types=["indicator"]`
- `Unit (mocked LLM): "High confidence malware from last week" → confidence_min=80, first_seen_after=7 days ago`
- `Unit (mocked LLM): "TTPs used by APT28" → relationship query with source=threat-actor, type=uses, target=attack-pattern`
- `Integration: natural language query → structured search executed, results returned with summary`
- `Integration: query with no results → summary says "No matching intelligence found"`

---

#### 10.2 — Conversational UI component

**What**: Build the frontend chat-style interface for natural language queries with result rendering.

**Design**:

```typescript
// src/frontend/src/components/query/ConversationalQuery.tsx
interface QueryMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  results?: StixObject[];
  query?: SearchQuery;
  followUpSuggestions?: string[];
  timestamp: string;
}
```

Features:
- Chat-style message thread
- Query suggestions (auto-complete from common patterns)
- Inline result cards (STIX object summaries)
- Click result to navigate to full object detail
- Follow-up suggestion chips
- Query history

**Testing**:
- `E2E: type natural language query → results appear in chat thread`
- `E2E: click follow-up suggestion → new query executed`
- `E2E: click result card → navigates to object detail`

---

## Phase 11: Business Context and Relevance Scoring

### Purpose

Implement organization-specific relevance scoring that filters global feed noise to surface only intelligence relevant to a given technology stack and industry. This addresses the "Industry/technology-specific relevance filtering" gap identified in the feature survey.

### Tasks

#### 11.1 — Organization threat profile configuration

**What**: Allow organizations to define their technology stack, industry, geography, and threat model for relevance scoring.

**Design**:

```python
# src/tip/schemas/auth.py
class OrganizationThreatProfile(BaseModel):
    tech_stack: list[str]           # ["kubernetes", "aws", "nodejs", "postgresql"]
    industries: list[str]           # ["financial-services", "banking"]
    geographies: list[str]          # ["US", "EU"]
    critical_assets: list[str]      # ["customer-pii", "payment-systems"]
    threat_priorities: list[str]    # ["ransomware", "data-exfiltration", "supply-chain"]
```

API endpoint:
- `PUT /api/v1/organizations/{id}/threat-profile` — update threat profile

**Testing**:
- `Integration: set threat profile → stored in organization.settings JSONB`
- `Integration: retrieve threat profile → correct values returned`

---

#### 11.2 — AI relevance scoring engine

**What**: Score each ingested indicator for relevance to the organization's threat profile.

**Design**:

```python
# src/tip/ai/relevance_scorer.py
class RelevanceScorer:
    async def score_indicator(
        self, indicator: dict, threat_profile: OrganizationThreatProfile
    ) -> dict:
        """Score indicator relevance to organization.
        Returns: {
            "relevance_score": 0-100,
            "reasons": ["Targets financial-services sector", "Exploits Kubernetes vulnerability"],
            "matched_profile_fields": ["industries", "tech_stack"]
        }
        """
        ...

    async def filter_feed_by_relevance(
        self, objects: list[dict], threat_profile: OrganizationThreatProfile, min_score: int = 30
    ) -> list[dict]:
        """Filter a batch of ingested objects by relevance score."""
        ...
```

Relevance scoring runs as a Celery task after feed ingestion, tagging each object with a relevance score stored in `stix_data` as a custom extension property.

**Testing**:
- `Unit (mocked LLM): indicator targeting "kubernetes" + org has "kubernetes" in tech_stack → relevance >= 70`
- `Unit (mocked LLM): indicator targeting "scada" + org has no OT → relevance <= 20`
- `Integration: feed ingestion triggers relevance scoring → objects tagged with scores`
- `Integration: search can filter by relevance_score >= threshold`

---

## Phase 12: Deployment, Hardening, and Documentation

### Purpose

Prepare the platform for production deployment: Dockerfile optimization, environment-specific configuration, security hardening (rate limiting, input validation, OWASP API Security compliance), monitoring endpoints, and deployment documentation.

### Tasks

#### 12.1 — Production Dockerfile and build optimization

**What**: Multi-stage Dockerfile with minimal runtime image, health checks, and non-root user.

**Design**:

```dockerfile
# Dockerfile
FROM python:3.12-slim AS builder
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install uv && uv sync --frozen --no-dev

FROM python:3.12-slim AS runtime
RUN useradd -m -r appuser
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .
ENV PATH="/app/.venv/bin:$PATH"
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8000/health || exit 1
CMD ["uvicorn", "src.tip.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
```

**Testing**:
- `Integration: docker build → image builds successfully`
- `Integration: docker-compose up → all services start and pass health checks`
- `Integration: API serves requests under non-root user`
- `Unit: image size < 500MB`

---

#### 12.2 — Security hardening

**What**: Implement rate limiting, input validation hardening, CORS tightening, and security headers per OWASP API Security Top 10.

**Design**:

```python
# Rate limiting with Redis
from fastapi import Request
from redis import asyncio as aioredis

class RateLimiter:
    async def check_rate_limit(
        self, key: str, max_requests: int, window_seconds: int
    ) -> bool: ...

# Rate limits per endpoint category:
RATE_LIMITS = {
    "auth": {"max_requests": 10, "window_seconds": 60},        # login/register
    "search": {"max_requests": 100, "window_seconds": 60},     # search queries
    "taxii": {"max_requests": 60, "window_seconds": 60},       # TAXII endpoints
    "enrichment": {"max_requests": 20, "window_seconds": 60},  # AI enrichment
    "default": {"max_requests": 200, "window_seconds": 60},    # all other endpoints
}

# Security headers middleware
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
}
```

**Testing**:
- `Integration: exceed rate limit → 429 Too Many Requests with Retry-After header`
- `Integration: login with 11 attempts in 60s → 429 on 11th attempt`
- `Integration: all responses include security headers`
- `Integration: SQL injection in search query → rejected (parameterized queries)`
- `Integration: XSS payload in STIX object name → escaped in API response`
- `Integration: CORS tightened to configured origins in production mode`

---

#### 12.3 — Monitoring and observability

**What**: Add Prometheus metrics endpoint, structured logging, and error tracking.

**Design**:

```python
# Prometheus metrics
from prometheus_fastapi_instrumentator import Instrumentator

# Custom metrics:
# - tip_stix_objects_total (gauge, by type)
# - tip_feed_polls_total (counter, by feed and status)
# - tip_enrichment_jobs_total (counter, by type and status)
# - tip_search_latency_seconds (histogram)
# - tip_taxii_requests_total (counter, by collection and method)

# Structured logging
import structlog
logger = structlog.get_logger()

# Usage:
logger.info("stix_object_created", stix_id=obj.stix_id, stix_type=obj.stix_type, org_id=str(org_id))
```

API endpoints:
- `GET /metrics` — Prometheus metrics
- `GET /health` — health check (already exists)
- `GET /health/ready` — readiness check (database + Redis + Celery worker)

**Testing**:
- `Integration: GET /metrics → Prometheus text format with custom metrics`
- `Integration: GET /health/ready with all services up → 200`
- `Integration: GET /health/ready with Redis down → 503`
- `Integration: structured log output includes correlation_id, user_id, org_id`

---

#### 12.4 — Deployment documentation and environment configuration

**What**: Create deployment guides for Docker Compose (development), Kubernetes (production), and standalone installations.

**Design**:

Environment-specific configuration:
```bash
# .env.example
TIP_DATABASE_URL=postgresql+asyncpg://tip:tip@localhost:5432/tip
TIP_REDIS_URL=redis://localhost:6379/0
TIP_JWT_SECRET_KEY=change-me-in-production
TIP_LLM_PROVIDER=anthropic
TIP_ANTHROPIC_API_KEY=sk-ant-...
TIP_DEBUG=false
TIP_DEFAULT_TLP_LEVEL=TLP:AMBER
```

**Testing**:
- `E2E: fresh docker-compose up from clean state → system boots, creates tables, serves API`
- `E2E: run alembic migrations on existing database → schema updated without data loss`

---

## Phase Summary & Dependencies

```
Phase 1: Foundation                         ─── required by everything
    │
Phase 2: Authentication & Authorization     ─── requires Phase 1
    │
Phase 3: STIX Object CRUD & Search          ─── requires Phase 2
    │
    ├── Phase 4: Feed Ingestion Engine       ─── requires Phase 3
    │       │
    │       └── Phase 5: TAXII 2.1 Server   ─── requires Phase 3 & 4
    │
    ├── Phase 6: ATT&CK & Detection Rules   ─── requires Phase 3
    │
    └── Phase 7: AI Enrichment Pipeline      ─── requires Phase 3 & 6
            │
            └── Phase 10: Conversational Query ─── requires Phase 7
                    │
                    └── Phase 11: Relevance Scoring ─── requires Phase 7 & 10

Phase 8: Frontend Dashboard                  ─── requires Phase 3 (can parallel with Phases 4-7)
    │
    └── Phase 9: Collaboration Workspaces    ─── requires Phase 8

Phase 12: Deployment & Hardening             ─── requires all phases (can start partially after Phase 3)
```

### Parallelism Opportunities

- **Phases 4, 6, 7** can be developed concurrently after Phase 3 is complete (all depend on STIX CRUD, independent of each other until Phase 7 needs Phase 6 for ATT&CK context in rule generation)
- **Phase 8 (Frontend)** can begin as soon as Phase 3 API endpoints are available, in parallel with backend Phases 4-7
- **Phase 12 (Deployment)** can begin security hardening and Dockerfile work as early as Phase 3
- **Phase 5 (TAXII Server)** can proceed in parallel with Phase 6/7 once Phase 4 feed management is done

---

## Definition of Done (per phase)

1. All tasks implemented as specified in the Design section
2. All unit tests pass (`pytest tests/unit/`)
3. All integration tests pass (`pytest tests/integration/`)
4. Ruff linting passes with zero errors (`ruff check src/`)
5. Ruff formatting is consistent (`ruff format --check src/`)
6. mypy type checking passes in strict mode (`mypy src/ --strict`)
7. Docker build succeeds (`docker build -t tip .`)
8. Docker Compose full stack boots and passes health checks
9. Alembic migrations run cleanly on fresh database (`alembic upgrade head`)
10. New API endpoints appear in auto-generated OpenAPI spec (`/openapi.json`)
11. New configuration options documented in `.env.example`
12. Frontend builds without errors (`pnpm build` in src/frontend/)
13. ESLint and Prettier pass on frontend code
14. Feature works end-to-end via API and (where applicable) frontend
