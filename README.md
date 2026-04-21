# Cloud Compliance Platform

A Docker-containerized platform for **continuous multi-cloud compliance monitoring** across AWS, Azure, and GCP. Provides a terminal-style TUI dashboard for managing security posture, framework compliance (PCI-DSS, HIPAA, GDPR, SOC 2, NIST, CIS, OWASP), data security, and misconfiguration violations.

All compliance scans, violation findings, and DSPM data security findings run against **live cloud infrastructure** — no simulated or dummy data.

---

## Core Features

| Feature | Description |
|---|---|
| **TUI Dashboard** | Grid-based React interface with trend charts, real-time metrics, and a per-framework score ring |
| **Violations Engine** | Queries live compliance failures; dynamically supports custom user policies; auto-cleans stale findings on each refresh |
| **DSPM** | Sensitive-data discovery from live cloud storage and databases; automated classification; per-account error isolation |
| **Correlation Layer** | Intersects DSPM data risk with infrastructure violations to surface exploitable attack paths |
| **Terraform Drift** | Ingests local/remote `.tfstate` to detect config drift against live cloud environments |
| **Remediation Engine** | YAML runbooks with cloud-native SDK rollback; dry-run guardrails; per-rule automation gate |
| **Multi-Cloud Connectors** | AWS, Azure, and GCP with unified resource enumeration |
| **ML Anomaly Detection** | Machine learning model on compliance metrics and threat intel features to reduce false positives |
| **Evidence Chain** | Cryptographic integrity proofs stored in object storage for tamper-proof audit evidence |
| **TOTP MFA** | Two-step login with authenticator-app TOTP; QR enrolment; one-time backup codes |
| **Compliance Score Engine** | Severity-weighted scoring with grade bands and per-framework adjustments; daily trend snapshots |
| **Approval Workflows** | 4-eyes change-management gate with full state machine and automatic expiry |
| **WebSocket Feed** | Org-scoped, authenticated live event stream with keepalive |
| **Brute-Force Protection** | Redis-backed account lockout after repeated login failures |
| **Prometheus Metrics** | `/metrics` endpoint protected by admin authentication and source-IP allowlist |
| **Invite-Only Registration** | New accounts require an admin-issued invite token; open self-registration is disabled |

---

## Feature Progression — April 2026

### Live Violations Engine (Real Data Integration)

The Violations Engine previously used a hardcoded simulated violations list. It has been fully replaced with a live database query:

- **Dynamic query**: fetches all compliance check failures joined with scan and account context for provider visibility
- **Custom policy support**: if a user-created policy produces a failure, the engine automatically tracks it; no code changes required
- **Clean refresh**: stale or resolved violations are automatically purged on each scan cycle
- **URN normalisation**: violations are keyed by `<provider>://<account_id>/<resource_type>/<resource_id>` for cross-module correlation with DSPM
- **Zero hardcoding**: the violation count tracks actual infrastructure failures in real time; adding or removing compliance checks is reflected immediately

### Live DSPM Engine (Real Data Integration)

The DSPM Engine previously used a hardcoded list of simulated data stores. It now queries live AWS environments:

- **Account iteration**: loops over all active cloud accounts and connects to each provider independently
- **Live data sources**: enumerates real S3 buckets and RDS instances — bucket names, public-access flags, and encryption states from AWS
- **Automated classification**: applies heuristic rules based on resource naming conventions and metadata to assign sensitivity levels and data categories
- **Per-account error isolation**: a failed connector (e.g. expired credentials) logs the error and skips to the next account without crashing the engine
- **Clean refresh**: decommissioned resources are automatically pruned on each scan cycle
- **Threat intel enrichment**: external CVE and reputation feeds are correlated against discovered resources

### Dashboard & UI Stabilisation

- **Modal Overlay Positioning**: Migrated Dashboard and Workflow modals (Remediation, Submit Approval, Approve/Reject) to use React Portals. This detaches them from parent container constraints, ensuring they render perfectly centered in the viewport regardless of page scroll depth or flexbox layouts.
- **Enhanced UI Readability**: Increased base font sizes, width, and padding across all modal interfaces to improve typographic hierarchy and readability.
- **NO DATA bug fixed**: Preliminary scans that completed with zero checks were rendering as `NO DATA` tiles; the frontend now filters these out before rendering.
- **Trend graph history**: Increased the scan history depth to ensure historical trend lines remain populated after frequent daily scans.
- **MFA Enrolment UI**: Integrated a dedicated Security Settings page allowing users to opt into TOTP-based Multi-Factor Authentication. The UI dynamically renders QR codes for setup and provides secure, one-time backup recovery codes.
- **2-Step Login Flow**: Upgraded the primary authentication screen to seamlessly intercept logins for MFA-enrolled accounts, enforcing a secondary 6-digit TOTP challenge before granting access to the platform.

### Workflow Engine Refinements

- **System Auto-Approvals**: Relaxed the 4-eyes rule for system-generated violation remediation requests. Administrators can now directly approve these automated requests, preventing workflow bottlenecks while still strictly enforcing the 4-eyes rule for human-initiated manual changes.
- **Backend Schema Stabilisation**: Resolved critical 500/502 Internal Server Errors during role resolution and ensured consistent frontend authorization states.

### Multi-Account Org Hierarchy & RBAC Isolation

3-tier org isolation (`Admin → Auditor → Customer`) enforced at every layer:

- **Organisational hierarchy**: full parent/child org relationships with account-level scoping; managed via versioned migrations
- **Session claims**: organisation context embedded in authenticated sessions; validated on every write operation
- **Scoped queries**: centralised query filter applied to all list endpoints ensuring data isolation between organisations
- **Auditor Assignment API** — `POST/DELETE/GET /api/v1/orgs/{id}/auditors`: admin grants/revokes scoped read access; idempotent
- **Time-limited grants**: auditor assignments support configurable expiration and soft-revocation
- **Inactive credential tracking**: login timestamps recorded for compliance with CIS 1.3 inactive-credential controls
- **Write guard**: auditor role is strictly read-only across all mutation endpoints

### Threat Intelligence Enrichment

Three external feeds correlated into DSPM findings and violation records:

| Feed | Integration |
|---|---|
| **NVD / NIST CVE** | CPE-based vulnerability search with response caching |
| **VirusTotal v3** | IP / domain reputation lookups with rate-limit awareness |
| **MISP** | Threat event search; opt-in via environment variable; fail-open |

- Threat intelligence data is periodically refreshed via scheduled background tasks to keep enrichment current
- Severity signals from external feeds contribute to the ML anomaly detection model's feature set

**Threat Intel API — `/api/v1/threat-intel/`:**

| Endpoint | Description |
|---|---|
| `GET /health` | Feed reachability and cache statistics |
| `POST /enrich` | Admin-triggered immediate enrichment run |
| `GET /cve/{resource_type}` | Cached CVE list for a resource type (e.g. `s3`, `rds`, `blob`) |
| `POST /cache/invalidate` | Force cache invalidation for a specific feed |

---

### TOTP Multi-Factor Authentication

Two-step login flow with authenticator-app TOTP. MFA is opt-in per user; all tokens are delivered via `HttpOnly; Secure; SameSite=Strict` cookies — never in response bodies or URL parameters:

- **Step 1** `POST /auth/login` — password verified; if MFA is enrolled, a short-lived challenge token is returned; the session is not established yet
- **Step 2** `POST /auth/mfa/verify` — exchange the challenge token + 6-digit TOTP (or a one-time backup code) for a full authenticated session (tokens set in secure cookies)
- **`POST /auth/mfa/enrol`**: generates a new TOTP secret and QR code for scanning; MFA is NOT active until `/mfa/confirm` is called
- **`POST /auth/mfa/confirm`**: verifies the first code to prove the user has scanned correctly, then activates MFA on the account
- **`POST /auth/mfa/disable`**: requires current TOTP or backup code to prove possession before disabling
- **Backup codes**: a set of one-time recovery codes are generated at enrolment, securely hashed, and consumed individually

### Compliance Score Engine

Severity-weighted scoring with grade bands and historical trends:

- **Severity weighting**: failing compliance checks contribute to the overall score according to their severity level
- **Framework adjustments**: different compliance frameworks carry different scoring weights based on their regulatory impact
- **DSPM penalty**: elevated data-security risk scores reduce the overall organisation compliance grade
- **Grade bands**: letter grades from A (highest) to F (lowest) are calculated from the weighted aggregate score
- **Trend history**: daily organisation-level snapshots are stored for historical trend analysis on the dashboard
- **Scheduled snapshots**: background tasks automatically capture score snapshots on a daily cadence

### Approval Workflows

4-eyes change-management gate for high-risk platform actions:

- **State machine**: `PENDING → APPROVED → EXECUTED` · `PENDING → REJECTED` · `PENDING → CANCELLED` · `PENDING → EXPIRED`
- **4-eyes rule**: the original requester cannot approve their own request
- **Role gate**: only `admin` and `auditor` roles can approve or reject; `dev`/`viewer` can only submit or cancel
- **Expiry**: requests expire after a configurable time window; stale requests are automatically marked as expired by a background sweep
- **Execution**: `POST /api/v1/workflows/requests/{id}/execute` (admin-only) dispatches to the remediation engine
- **Audit trail**: every approval decision records the reviewer, timestamp, and notes for full traceability

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

### WebSocket Real-Time Dashboard

Org-scoped live event feed for real-time dashboard updates:

- **Scoped channels**: each organisation receives events only for its own resources; worker processes publish, and the connection manager fans out to all connected clients
- **Auth**: authenticated via a short-lived, single-use ticket obtained from `POST /api/v1/auth/ws-ticket`. The ticket is a random token (not the session JWT) stored in Redis with a 60-second TTL; it is consumed immediately on first use and cannot be reused
- **Event types streamed**: scan completions, violation detections, score updates, approval state changes, alerts, and remediation results
- **Auto-reconnect**: the server-side listener automatically recovers from transient connection failures
- **Fail-open**: event publishing never blocks or crashes the caller on delivery failure
- **Keepalive**: client sends `ping`; server echoes `pong`
- **WS endpoint**: `wss://<host>/api/v1/ws/live`

### Security Hardening & CI/CD Patches (Late April 2026)

- **RS256 JWT Signing**: Migrated from symmetric (HS256) to asymmetric (RS256) JWT signing. Tokens are signed with an RSA-2048 private key; any service only needs the public key to verify. A zero-downtime dual-verify migration mode exists but is disabled in production.
- **Cookie-Based Auth Transport**: All session tokens (`access_token`, `refresh_token`) are delivered exclusively via `HttpOnly; Secure; SameSite=Strict` cookies, mitigating XSS token theft.
- **API & Authentication Hardening:** Resolved `307 Temporary Redirect` errors by normalizing API routes. Fixed `HttpOnly` cookie path scoping to prevent unintended token exposure.
- **Infrastructure Stability:** Fixed bind mount permission errors for non-root containers on Windows hosts. Corrected worker SSL verification by securely mounting CA certificates into named Docker volumes, and removed keys from the backend build context.
- **Role-Based Access Control (RBAC):** UI remediation buttons (`FIX` / `APPROVE`) are now dynamically protected. `Admin` and `Auditor` roles retain access, while `Dev` and `Viewer` accounts are restricted to a `VIEW ONLY` state.
- **Dashboard & Alerts UI/UX:** Resolved layout overflow issues where log tables expanded beyond their container boundaries. Tables now scroll internally within perfectly bounded visual frames.
- **Modal Portals:** Migrated all modals to React Portals for consistent viewport centering regardless of parent container constraints.
- **CI Security Scans**: Secret scanning (Gitleaks), dependency audits (pip-audit, npm audit), and container scanning (Trivy) run on every push. Scans are report-only and non-blocking to avoid upstream transitive CVEs halting valid deployments.

---

## Architecture

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                      Cloud Compliance Platform                          │
├──────────┬───────────────────────────────────────────────┬──────────────┤
│  Nginx   │                                               │              │
│  TLS     │               FastAPI REST API                │  OPA Engine  │
│  Proxy   │───────────────────────────────────────────────│  Rego / YAML │
│ (443/80) │  DSPM  │  Violations  │  Remediations         │──────────────┤
│          │                                               │  Workflows   │
│  React   │  Background Workers (scan, enrich, sweep)     │  & RBAC      │
│  TUI     │                                               │              │
├──────────┴───────────────────────────────────────────────┴──────────────┤
│   PostgreSQL (async ORM)   │   Redis (cache + pub/sub)   │   MinIO     │
│   Versioned Migrations     │                             │  (Evidence) │
│                            │                             │  ML Engine  │
└──────────────────────────────────────────────────────────────────────────┘
  ↕ AWS          ↕ Azure              ↕ GCP
        ↕ NVD/NIST      ↕ VirusTotal      ↕ MISP
```

---

## Quick Start

### Prerequisites

- Docker Desktop 4.x+
- Docker Compose 2.x+
- `openssl` (for certificate and key generation — available by default on macOS/Linux; use Git Bash or WSL on Windows)

### 1. Clone the repository

```bash
git clone https://github.com/Ashishshaik91/Automated_Cloud_Compliance.git
cd Automated_Cloud_Compliance
```

### 2. Generate TLS certificates

Required for Nginx HTTPS and OPA's internal TLS. Run once before first start:

```bash
bash scripts/gen_certs.sh
```

This creates `nginx/certs/cert.pem` and `nginx/certs/key.pem`. Your browser will show a self-signed certificate warning — click **Advanced → Proceed** to access the app. All TLS encryption is fully active.

### 3. Generate JWT signing keys

Required for RS256 JWT authentication:

```bash
bash scripts/gen_jwt_keys.sh
```

This creates `backend/keys/jwt_private.pem` and `backend/keys/jwt_public.pem`. These files are gitignored and must never be committed.

### 4. Configure environment

```bash
cp .env.example .env
# Fill in all secrets — see .env.example for required keys
```

### 5. Start the full stack

```bash
docker compose up -d --build
```

### 6. Access the platform

| Service | URL |
|---|---|
| **TUI Dashboard** | https://localhost |
| **API** | https://localhost/api/ |
| **API Docs (Swagger)** | Disabled in production mode (`APP_ENV=production`) |

> **Note:** All traffic is served through the Nginx TLS reverse proxy on port 443. Internal services (database, cache, object storage, policy engine) are not exposed to the host network. Swagger UI is disabled when the stack runs in production mode for security reasons.

### 7. Default credentials

| Role | Email | Password |
|---|---|---|
| Admin | `admin@compliance.local` | set in `.env` |
| Auditor | `auditor@compliance.local` | set in `.env` |
| Developer | `dev@compliance.local` | set in `.env` |

> **Note:** These users are seeded automatically on first startup. New user accounts beyond the seeds require an admin-issued invite token — there is no open self-registration endpoint.

---

## Project Structure

```text
CloudCompliancePlatform/
├── backend/
│   ├── app/
│   │   ├── api/              # REST routers (threat-intel, orgs, violations, dspm, workflows, ...)
│   │   ├── auth/             # Authentication, session management, org scoping, MFA helpers
│   │   ├── connectors/       # AWS / Azure / GCP / Terraform resource fetching
│   │   ├── core/             # Scanner, DSPM, remediation, score engine, workflow engine, workers
│   │   ├── integrations/     # NVD, VirusTotal, MISP clients with response caching
│   │   ├── ml/               # Anomaly detection model
│   │   ├── models/           # ORM models
│   │   ├── schemas/          # Request/response schemas
│   │   └── ws/               # WebSocket connection manager, router, publisher
│   ├── alembic/versions/     # Database migrations
│   ├── keys/                 # RSA JWT key pair (gitignored — generated by scripts/gen_jwt_keys.sh)
│   ├── policies/             # YAML compliance definitions
│   ├── secrets/              # Cloud credentials and CA certificates (gitignored)
│   └── tests/                # Pytest suite
├── frontend/                 # React 18 + Vite TUI
│   ├── src/                  # React components, pages, and API clients
│   └── nginx.conf            # Internal frontend web server configuration
├── infra/                    # Terraform demo stack and resource management scripts
├── nginx/                    # TLS Reverse Proxy configuration
│   ├── nginx.conf            # Reverse proxy config (ports 80/443, rate limiting, security headers)
│   └── certs/                # TLS certificates (gitignored — generated by scripts/gen_certs.sh)
├── opa/                      # OPA Rego policies
├── scripts/                  # Setup utilities
│   ├── gen_certs.sh          # Generate self-signed TLS cert for Nginx and OPA
│   ├── gen_jwt_keys.sh       # Generate RSA-2048 key pair for RS256 JWT signing
│   └── generate_rego.py      # Convert YAML policy definitions to OPA Rego
├── .github/workflows/        # GitHub Actions CI/CD (ci.yml) and Security scanning (security.yml)
└── docker-compose.yml
```

---

## Security Posture

| Control | Implementation |
|---|---|
| **Secrets management** | All credentials via environment variables; never committed to source |
| **JWT signing** | RS256 (RSA-2048 asymmetric key pair); HS256 fallback disabled in production |
| **Authentication transport** | All session tokens delivered exclusively via `HttpOnly; Secure; SameSite=Strict` cookies |
| **Token revocation** | Logout adds both access and refresh token identifiers to a Redis denylist for their remaining lifetime |
| **Password hashing** | Industry-standard memory-hard hashing algorithm (Argon2) |
| **Brute-force protection** | Redis-backed account lockout after repeated failed login attempts |
| **Registration** | Invite-token gated; admin issues time-limited tokens; open self-registration is disabled |
| **Multi-tenancy isolation** | Organisation-scoped query filtering on all data access; auditor write guard |
| **Auditor grants** | Time-limited with configurable expiration and soft-revocation |
| **Audit trail** | Structured events recorded on every mutating API call |
| **Evidence integrity** | Cryptographic integrity proofs in object storage |
| **Input validation** | Schema-validated request/response models; parameterised queries only |
| **CORS enforcement** | Restricted to configured origins; `http://` origins rejected at startup in production |
| **Rate limiting** | slowapi application-layer rate limiting + Nginx-level `limit_req` zones (login, API, WebSocket) |
| **Container hardening** | Non-root user, `no-new-privileges` security option, no host port exposure except TLS proxy |
| **OPA TLS** | OPA runs with TLS; backend verifies OPA's certificate via a mounted CA cert — `verify=False` is never used |
| **Prometheus metrics** | `/metrics` requires admin authentication AND source-IP allowlist; non-allowed IPs receive a stealth 404 |
| **Dependency scanning** | Gitleaks (secret scan), pip-audit, npm audit, and Trivy container scan in CI — report-only mode |
| **Inactive credentials** | Login timestamps tracked for compliance with CIS 1.3 inactive-credential controls |
| **TOTP MFA** | Two-step login with authenticator-app TOTP; one-time backup codes; enrol/confirm/disable lifecycle |

---

## Supported Compliance Frameworks

| Framework | Version | Policy Engine |
|---|---|---|
| **PCI-DSS** | v4.0 | OPA Rego + YAML |
| **HIPAA** | Security Rule | OPA Rego + YAML |
| **GDPR** | 2016/679 | OPA Rego + YAML |
| **SOC 2** | Type II | OPA Rego + YAML |
| **NIST** | CSF 2.0 | OPA Rego + YAML |
| **CIS** | Benchmarks v8 | OPA Rego + YAML |
| **OWASP** | Top 10 | OPA Rego + YAML |

---

## Cloud Infrastructure Remediation

The platform ships with executable remediation scripts that can be triggered via Terraform or run directly inside the backend container:

| Script | Purpose |
|---|---|
| `run_mfa.sh` | Entrypoint: chains MFA + CloudTrail/IAM remediation scripts |
| `enable_mfa.py` | Enables virtual MFA for demo IAM users |
| `fix_cloudtrail_and_iam.py` | Deactivates stale IAM access keys; updates CloudTrail log-file validation and multi-region settings |

> **Credential requirement**: CloudTrail updates require an IAM identity with administrative CloudTrail permissions. The read-only compliance role will receive `AccessDenied` for trail mutations — use AWS CloudShell or a privileged role for those calls.

### Manual CloudTrail Fix (AWS CloudShell)

```bash
aws cloudtrail update-trail --name TrailTesting --is-multi-region-trail --enable-log-file-validation
```

---

## CI/CD

Two GitHub Actions workflows (`.github/workflows/`):

**`ci.yml`** — runs on every push to `main`/`develop` and on pull requests:
- Backend linting and static analysis (ruff)
- Backend type checking (mypy)
- Python dependency security audit (pip-audit)
- Backend unit tests with coverage threshold enforcement
- Frontend build validation
- Docker image build validation

**`security.yml`** — runs on every push to `main`/`master`:
- Secret scanning across full Git history (Gitleaks)
- Python dependency audit (pip-audit) — report-only
- Node dependency audit (npm audit) — critical severity, report-only
- Container vulnerability scan (Trivy) — report-only

> Security scans run in report-only mode. This prevents transitive upstream vulnerabilities in third-party packages from blocking valid deployments while still generating a full audit record on every push.

---

## Key Dependencies

```
fastapi · uvicorn · sqlalchemy[asyncio] · asyncpg · alembic
redis · celery · slowapi · pydantic-settings · argon2-cffi
pyotp · qrcode[pil] · Pillow · python-jose[cryptography]
boto3 · azure-mgmt-* · google-cloud-* · httpx · aiohttp
scikit-learn · pandas · joblib · pyod
minio · reportlab · jinja2 · slack-sdk · sendgrid
structlog · prometheus-fastapi-instrumentator
```

---

## Author

GitHub: [@Ashishshaik91](https://github.com/Ashishshaik91)

## License

MIT License — © 2026 Cloud Compliance Platform
