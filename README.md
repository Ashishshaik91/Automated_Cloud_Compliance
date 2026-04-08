# Cloud Compliance Platform

A Docker-containerized SaaS platform for continuous multi-cloud compliance monitoring across AWS, Azure, and GCP. Provides a terminal-style TUI dashboard for managing security posture, framework compliance (PCI-DSS, HIPAA, GDPR, SOC 2, NIST, CIS, OWASP), data security, and misconfiguration violations.

---

## Core Features

| Feature | Description |
|---|---|
| **TUI Dashboard** | Grid-based React interface with trend charts, real-time metrics, and a per-framework score ring |
| **Violations Engine** | Rule-based configuration checks against OPA/Rego + YAML policies; 40+ rules across 8 frameworks |
| **DSPM** | Sensitive-data discovery with classification (PII, PHI, PCI) and impact-based risk scoring |
| **Correlation Layer** | Intersects DSPM data risk with infrastructure violations to surface exploitable attack paths |
| **Terraform Drift** | Ingests local/remote `.tfstate` to detect config drift against live cloud environments |
| **Remediation Engine** | YAML runbooks with cloud-native SDK rollback; `dry_run` guardrails; per-rule automation gate |
| **Multi-Cloud Connectors** | AWS (`boto3`), Azure (`azure-mgmt-*`), GCP (`google-cloud-*`) with unified resource enumeration |
| **ML Anomaly Detection** | Isolation Forest on compliance metrics + threat intel features to reduce false positives |
| **Evidence Chain** | SHA-256 hash chains + HMAC signatures stored in MinIO for tamper-proof audit evidence |

---

## Feature Progression — April 2026

### ✅ Multi-Account Org Hierarchy & RBAC Isolation

3-tier org isolation (`Admin → Auditor → Customer`) enforced at every layer:

- **DB schema**: `organizations` table with parent/child hierarchy; `cloud_accounts.organization_id` FK; Alembic migration `0001`
- **JWT claims**: `org_id` embedded in access token; DB re-validates all writes
- **`apply_org_scope()`**: centralised `WHERE organization_id IN (...)` injection used by every list endpoint
- **Auditor Assignment API** — `POST/DELETE/GET /api/v1/orgs/{id}/auditors`: admin grants/revokes scoped read access; idempotent
- **Time-limited grants**: `auditor_org_assignments.expires_at` + `is_active` (migration `0002`) — `get_org_scope()` filters by both
- **`last_login_at`** stamped on every login for CIS 1.3 inactive-credential detection (migration `0002`)
- **`require_write_access()`**: auditor role is strictly read-only across all mutation endpoints

### ✅ Threat Intelligence Enrichment

Three external feeds fanned out into DSPM findings and violation rows:

| Feed | Integration | Rate Limit |
|---|---|---|
| **NVD / NIST CVE** | `httpx` CPE v2 search | Redis 24h cache; batched by resource type |
| **VirusTotal v3** | IP / domain reputation | Redis sliding-window (4 req/min free tier) |
| **MISP** | REST event search | Opt-in via `MISP_URL` env var; fail-open |

**Changes:**
- `enrich_with_threat_intel()` queries NVD + VT + MISP; VT uses the actual public bucket hostname (replaces former `"0.0.0.0"` placeholder)
- `violations.cve_ids` and `violations.cvss_max` populated via `enrich_open_violations()` — previously always `NULL`
- ML Anomaly Detector: `cvss_max`, `vt_reputation`, `threat_intel_boost` added as Isolation Forest features
- Celery Beat: `scheduled-threat-intel-enrichment` runs every 6 hours, re-enriching stale records (>24h)
- MISP severity → score boost: High (`threat_level=1`) → +15, Medium → +8

**Threat Intel API — `/api/v1/threat-intel/`:**

| Endpoint | Description |
|---|---|
| `GET /health` | Feed reachability + Redis cache stats |
| `POST /enrich` | Admin-triggered immediate enrichment run |
| `GET /cve/{resource_type}` | Cached CVE list for a resource type (e.g. `s3`, `rds`, `blob`) |
| `POST /cache/invalidate` | Force Redis cache bust for a feed + key |

---

## Upcoming Sprint

Four features in active development — see `implementation_plan.md` for full specs:

| Feature | Key Additions |
|---|---|
| **TOTP MFA** | Two-step login via short-lived `mfa_pending` JWT (5 min); TOTP verify ±1 window; 8×8-char hashed backup codes; admin force-reset |
| **Compliance Score Engine** | Weighted scoring (severity × framework multiplier); grade bands A–F; daily trend snapshots |
| **Approval Workflows** | 4-eyes rule; `PENDING → APPROVED → EXECUTED / REJECTED / EXPIRED / CANCELLED` state machine; Celery expiry sweep |
| **WebSocket Real-Time Dashboard** | Redis pub/sub per org; JWT query-param auth on handshake; live event feed; event ticker UI |

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│                     Cloud Compliance Platform                       │
├─────────────┬──────────────────────────────────────┬───────────────┤
│    React    │          FastAPI REST API             │  OPA Engine   │
│TUI Dashboard│──────────────────────────────────────│  Rego / YAML  │
│  (Vite 5)  │  DSPM  │  Violations  │  Remediations │───────────────┤
│  WebSocket ←──── Redis pub/sub ───────────────────→  Celery Beat  │
├─────────────┴──────────────────────────────────────┴───────────────┤
│   PostgreSQL (SQLAlchemy async)  │  Redis  │  MinIO (Evidence)     │
│   Alembic Migrations (0001-0005) │         │  ML Anomaly Detector  │
└─────────────────────────────────────────────────────────────────────┘
  ↕ AWS (boto3)   ↕ Azure (azure-mgmt-*)   ↕ GCP (google-cloud-*)
        ↕ NVD/NIST      ↕ VirusTotal      ↕ MISP
```

---

## Quick Start

### Prerequisites

- Docker Desktop 4.x+
- Docker Compose 2.x+

### 1. Clone and configure

```bash
git clone https://github.com/Ashishshaik91/Automated_Cloud_Compliance.git
cd Automated_Cloud_Compliance
cp .env.example .env
# Fill in secrets — see .env.example for required keys
```

### 2. Start the full stack

```bash
docker compose up -d --build
```

### 3. Access the platform

| Service | URL |
|---|---|
| **TUI Dashboard** | http://localhost:3000 |
| **API** | http://localhost:8000 |
| **API Docs (Swagger)** | http://localhost:8000/api/docs |
| **MinIO Console** | http://localhost:9001 |
| **OPA Engine** | http://localhost:8181 |

### 4. Default credentials

| Role | Email | Password |
|---|---|---|
| Admin | `admin@compliance.local` | set in `.env` |
| Auditor | `auditor@compliance.local` | set in `.env` |
| Developer | `dev@compliance.local` | set in `.env` |

---

## Project Structure

```text
CloudCompliancePlatform/
├── backend/
│   ├── app/
│   │   ├── api/              # REST routers (threat-intel, orgs, violations, dspm, workflows, ...)
│   │   ├── auth/             # JWT, dependencies, org scoping, totp helpers
│   │   ├── connectors/       # AWS / Azure / GCP / Terraform resource fetching
│   │   ├── core/             # Scanner, DSPM, remediation, score engine, workflow engine, Celery
│   │   ├── integrations/     # NVD, VirusTotal, MISP clients + Redis cache
│   │   ├── ml/               # Isolation Forest anomaly detector
│   │   ├── models/           # SQLAlchemy ORM models
│   │   ├── schemas/          # Pydantic v2 schemas
│   │   └── ws/               # WebSocket connection manager, router, publisher
│   ├── alembic/versions/     # Migrations: 0001 org hierarchy · 0002 scoping · 0003 MFA · 0004 scores · 0005 workflows
│   ├── policies/             # YAML compliance definitions
│   └── tests/                # Pytest suite
├── frontend/                 # React 18 + Vite TUI
├── infra/                    # Terraform demo stack
├── opa/                      # OPA Rego policies
├── .github/workflows/        # GitHub Actions CI/CD
└── docker-compose.yml
```

---

## Security Posture

| Control | Implementation |
|---|---|
| **Secrets management** | All credentials via ENV vars (`Pydantic SecretStr`) |
| **Authentication** | JWT HS256 · 30 min access + 7 day refresh tokens |
| **Password hashing** | Argon2 (`argon2-cffi`) |
| **Multi-tenancy isolation** | Org-scoped `WHERE` injection; auditor write guard |
| **Auditor grants** | Time-limited (`expires_at`) + soft-revocable (`is_active`) |
| **Audit trail** | Structured JSON events on every mutating call |
| **Evidence integrity** | SHA-256 hash chains + HMAC (MinIO) |
| **Input validation** | Pydantic v2; no raw SQL |
| **Container hardening** | Non-root user, read-only FS |
| **Dependency scanning** | `pip-audit` in CI |
| **Inactive credentials** | `last_login_at` stamps for CIS 1.3 |
| **TOTP MFA** | Two-step login via short-lived `mfa_pending` JWT (5 min); `pyotp` TOTP verify ±1 window; 8×8-char hashed backup codes; admin force-reset *(upcoming sprint)* |

---

## Supported Compliance Frameworks

| Framework | Version | Policy Engine |
|---|---|---|
| **PCI-DSS** | v4.0 | OPA Rego + YAML |
| **HIPAA** | Security Rule | YAML |
| **GDPR** | 2016/679 | YAML |
| **SOC 2** | Type II | YAML |
| **NIST** | CSF 2.0 | YAML |
| **CIS** | Benchmarks v8 | YAML |
| **OWASP** | Top 10 | YAML |

---

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`):

- `ruff` + `eslint` static analysis
- `mypy` type checking
- `pip-audit` dependency security scanning
- `pytest` with coverage thresholds
- Frontend `npm run build` validation
- Docker build validation

---

## Key Dependencies

```
fastapi · uvicorn · sqlalchemy[asyncio] · asyncpg · alembic
redis · celery · pydantic-settings · python-jose[cryptography] · argon2-cffi
boto3 · azure-mgmt-* · google-cloud-* · httpx · aiohttp
scikit-learn · pandas · pyod · joblib
structlog · prometheus-fastapi-instrumentator
minio · reportlab · jinja2 · slack-sdk
```

---

## Author

GitHub: [@Ashishshaik91](https://github.com/Ashishshaik91)

## License

MIT License — © 2026 Cloud Compliance Platform
