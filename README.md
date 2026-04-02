# 🛡️ Cloud Compliance Platform

A production-grade, Docker-containerized SaaS platform for continuous multi-cloud compliance monitoring across **AWS, Azure, and GCP**. Built with a sleek, terminal-inspired TUI dashboard to manage security posturing, framework compliance (**PCI-DSS, HIPAA, GDPR, SOC 2, NIST, CIS, OWASP**), data security, and misconfiguration violations.

## ✨ Key Features

- **TUI-inspired Dashboard**: A highly immersive, grid-based React interface reminiscent of terminal multiplexers (`i3`/`tmux`). Features real-time system metrics (`system_info.sh`), dynamic trend charts (`security_trend.log`), and strict proportional layouts.
- **Violations Engine**: Advanced rule-based configuration checks evaluating cloud infrastructure against OPA/Rego policies and industry frameworks to detect misconfigurations.
- **DSPM (Data Security Posture Management)**: Automated discovery of sensitive cloud payloads, deep data classification (PII, PHI, Credentials), and impact-based data risk scoring.
- **Correlation Layer**: Intelligently intersects DSPM data risk with underlying infrastructure Violations to instantly surface, map, and prioritize critical, weaponizable attack paths.

## 🚀 Recent Updates & Progression (April 2026)

- **Terraform State Ingestion & Drift Mapping**: Seamlessly ingest local or remote (`S3`, `GCS`, `Azure Blob`) `.tfstate` files to detect configuration drift against live environments side-by-side.
- **Remediation Runbooks & Engine**: Dynamic YAML-backed remediation runbooks featuring explicit automated cloud-native rollback commands (e.g., AWS CLI, Azure CLI), protected by native per-org `dry_run` safety guardrails.
- **Multi-Account Org Isolation (RBAC)**: Complete multi-tenant API scoping across Admin, Auditor, and Customer tiers, fully permeating background Celery workers and Postgres databases via Alembic migrations.
- **Threat Intel Risk Enrichment**: Extends DSPM anomaly calculations by aggregating dynamic external intelligence—such as VT IP Reputations and automated NVD/CVE mapping—incorporating fail-open, rate-limited architectural patterns.

## 🏗️ Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                  Cloud Compliance Platform                   │
├─────────────┬────────────────────────────────┬───────────────┤
│    React    │          FastAPI REST API      │   OPA Engine  │
│TUI Dashboard│────────────────────────────────│  Rego/YAML    │
├─────────────┤ DSPM Module │Violations Engine │───────────────┤
│ System Info │┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈│   Celery      │
│ Trend Charts│       Correlation Layer        │   Worker      │
├─────────────┴────────────────────────────────┴───────────────┤
│          PostgreSQL  │  Redis  │  MinIO  │  ML Detector      │
└──────────────────────────────────────────────────────────────┘
       ↕ AWS (boto3)  ↕ Azure (azure-mgmt)  ↕ GCP (google-cloud)
```

## 🚀 Quick Start

### Prerequisites
- Docker Desktop 4.x+
- Docker Compose 2.x+

### 1. Clone and configure

```bash
git clone https://github.com/Ashishshaik91/Automated_Cloud_Compliance.git
cd Automated_Cloud_Compliance

# Copy and fill in your environment variables
cp .env.example .env
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
| **API Docs** | http://localhost:8000/api/docs |
| **MinIO Console** | http://localhost:9001 |
| **OPA Engine** | http://localhost:8181 |

## 📋 Project Structure

```text
Automated_Cloud_Compliance/
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── api/             # REST endpoints (alerts, scans, dspm, violations)
│   │   ├── auth/            # JWT authentication
│   │   ├── connectors/      # AWS / Azure / GCP resource fetching
│   │   ├── core/            # Correlation layer, scanners, remediation
│   │   ├── ml/              # Anomaly detection models
│   │   ├── models/          # SQLAlchemy DB schema
│   │   ├── schemas/         # Pydantic validation
│   │   └── utils/           # Utilities, crypto, hashing
│   ├── policies/            # YAML standard compliance definitions
│   └── tests/               # Pytest suite
├── frontend/                 # React 18 + Vite TUI Dashboard
├── opa/                      # Open Policy Agent Rego policies
├── .github/workflows/        # GitHub Actions CI/CD pipelines
└── docker-compose.yml        # Full stack orchestration
```

## 🔐 Security Standards

| Standard | Implementation |
|---|---|
| **No hardcoded secrets** | All credentials via ENV vars (Pydantic settings) |
| **Auth** | JWT (HS256) with short expiry + refresh tokens |
| **Password storage** | bcrypt with 12 rounds |
| **HTTPS** | TLS termination at Nginx reverse proxy |
| **Input validation** | Pydantic v2 on all API inputs |
| **SQL injection prevention**| SQLAlchemy ORM only (no raw SQL execution) |
| **Container hardening** | Non-root user, read-only filesystems |
| **Audit logging** | Structured JSON logs |
| **Evidence integrity** | SHA-256 hash chains + HMAC signing |

## 📊 Supported Compliance Frameworks

| Framework | Version |
|---|---|
| **PCI-DSS** | v4.0 |
| **HIPAA** | Security Rule |
| **GDPR** | 2016/679 |
| **SOC 2** | Type II |
| **NIST** | CSF |
| **CIS** | Benchmarks |
| **OWASP** | Top 10 |

## 🔄 CI/CD

GitHub Actions pipeline (`.github/workflows/ci.yml`) runs continuous checks:
- ✅ `ruff` / `eslint` static analysis
- ✅ `mypy` type validation
- ✅ `pip-audit` dependency security scanning
- ✅ `pytest` test suites with coverage thresholds
- ✅ Frontend `npm build` bundling
- ✅ Docker immutability & build validation

## 👤 Author
- GitHub: [@Ashishshaik91](https://github.com/Ashishshaik91)

## 📄 License
MIT License — © 2026 Cloud Compliance Platform
