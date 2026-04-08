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
| **TOTP MFA** | Two-step login with TOTP verify ±1 window; QR enrolment; 8×8-char hashed backup codes |
| **Compliance Score Engine** | Weighted severity scoring; grade bands A–F; per-framework multipliers; daily snapshot trend |
| **Approval Workflows** | 4-eyes change-management gate; full state machine; Celery expiry sweep |
| **WebSocket Feed** | Redis pub/sub per org; JWT-authenticated live event stream; ping/pong keepalive |

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

### ✅ TOTP Multi-Factor Authentication

Two-step login flow with authenticator-app TOTP (`pyotp`):

- **Step 1** `POST /auth/login` — password verified; if MFA enrolled returns `{ mfa_required: true, mfa_token }` (5-min JWT)
- **Step 2** `POST /auth/mfa/verify` — exchange `mfa_token` + 6-digit TOTP (or 8-char backup code) for full session tokens
- **`POST /auth/mfa/enrol`**: generates a new TOTP secret + base64 QR PNG; MFA is NOT active until `/mfa/confirm` is called
- **`POST /auth/mfa/confirm`**: verifies first code to prove the user has scanned correctly, then sets `mfa_enabled = true`
- **`POST /auth/mfa/disable`**: requires current TOTP or backup code to prove possession before disabling
- **Backup codes**: 8 × 8-char uppercase codes, hashed with Argon2; consumed one-at-a-time and removed after use
- **Migration `0003`**: adds `mfa_secret`, `mfa_enabled`, `mfa_backup_codes (JSON)`, `mfa_enrolled_at` columns to `users`

### ✅ Compliance Score Engine

Weighted scoring with grade bands and historical trends:

- **Severity weights**: CRITICAL→10, HIGH→5, MEDIUM→2, LOW→1 — failing checks deduct proportional weight
- **Framework multipliers**: PCI-DSS/HIPAA→1.3, GDPR→1.2, SOC 2→1.1, NIST/CIS→1.0, OWASP→0.9
- **DSPM penalty**: each 10 points of average DSPM risk score subtracts 1 from the org-level aggregate
- **Grade bands**: A (≥90), B (≥75), C (≥60), D (≥45), F (<45)
- **`ScoreSnapshot`**: daily org-level snapshot stored in `score_snapshots` for 90-day trend history
- **`AccountScoreCache`**: latest per-account per-framework score for fast dashboard reads
- **Celery Beat**: `daily-score-snapshot` runs at 00:05 UTC across all active orgs
- **Migration `0004`**: creates `score_snapshots` and `account_score_cache` tables

### ✅ Approval Workflows

4-eyes change-management gate for high-risk platform actions:

- **State machine**: `PENDING → APPROVED → EXECUTED` · `PENDING → REJECTED` · `PENDING → CANCELLED` · `PENDING → EXPIRED`
- **4-eyes rule**: enforced in `approve_request()` — requester cannot approve their own request; raises `PermissionError`
- **Role gate**: only `admin` and `auditor` roles can approve or reject; `dev`/`viewer` can only submit or cancel
- **Expiry**: requests expire after 24 hours by default (configurable per-request up to 168 h); checked at approval time
- **Celery Beat**: `expire-stale-approvals` sweeps every hour — marks PENDING+expired rows as EXPIRED in bulk
- **Execution**: `POST /api/v1/workflows/requests/{id}/execute` (admin-only) dispatches to the remediation engine
- **Audit trail**: `execution_result` JSON stored on the row; `reviewed_at`, `approver_id`, `notes` always recorded
- **Migration `0005`**: creates `approval_requests` table with status, risk level, expiry, and execution_result columns

**Approval Workflow API — `/api/v1/workflows/`:**

| Endpoint | Description |
|---|---|
| `POST /requests` | Submit a new approval request |
| `GET /requests` | List requests (role-scoped: admin/auditor see org; dev sees own) |
| `GET /requests/{id}` | Request detail |
| `POST /requests/{id}/approve` | Approve with optional notes |
| `POST /requests/{id}/reject` | Reject with mandatory notes |
| `POST /requests/{id}/cancel` | Cancel (requester or admin only) |
| `POST /requests/{id}/execute` | Execute approved action (admin only) |

### ✅ WebSocket Real-Time Dashboard

Org-scoped live event feed via Redis pub/sub:

- **Channel pattern**: `compliance:live:{org_id}` — one Redis channel per org; workers publish, manager fans-out to all org WS clients
- **Auth**: JWT passed as query param `?token=<access_token>` (browser WS does not support custom headers)
- **Event types streamed**: `scan.completed`, `violation.detected`, `score.updated`, `approval.pending`, `alert.fired`, `remediation.result`
- **Reconnect**: Redis listener runs as an asyncio background task with an infinite reconnect loop (5s backoff)
- **Fail-open**: `publish_event()` catches all Redis errors and logs a warning — never raises to the caller
- **Keepalive**: client sends `ping` text frame; server echoes `pong`
- **WS endpoint**: `ws://host/api/v1/ws/live?token=`

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
| **TOTP MFA** | Two-step login; `mfa_pending` JWT (5 min); `pyotp` TOTP verify ±1 window; 8×8-char Argon2-hashed backup codes; `/mfa/enrol`, `/mfa/confirm`, `/mfa/disable` |

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
pyotp · qrcode[pil] · Pillow
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
