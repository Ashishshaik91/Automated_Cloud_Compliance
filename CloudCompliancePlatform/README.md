# 🛡️ Cloud Compliance Platform

A production-grade, Docker-containerized SaaS platform for continuous multi-cloud compliance monitoring across **AWS, Azure, and GCP**, supporting **PCI-DSS, HIPAA, GDPR, and SOC 2** frameworks.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               Cloud Compliance Platform                      │
├─────────────┬───────────────┬──────────────┬───────────────┤
│   React     │   FastAPI     │   Celery     │   OPA Engine  │
│  Dashboard  │   REST API    │   Worker     │  Rego/YAML    │
├─────────────┴───────────────┴──────────────┴───────────────┤
│         PostgreSQL  │  Redis  │  MinIO  │  ML Detector      │
└──────────────────────────────────────────────────────────────┘
       ↕ AWS (boto3)  ↕ Azure (azure-mgmt)  ↕ GCP (google-cloud)
```

## 🚀 Quick Start

### Prerequisites
- Docker Desktop 4.x+
- Docker Compose 2.x+

### 1. Clone and configure

```bash
git clone https://github.com/yourorg/cloud-compliance-platform.git
cd CloudCompliancePlatform

# Copy and fill in your environment variables
cp .env.example .env
# Edit .env with your credentials (DB passwords, cloud creds, etc.)
```

### 2. Start the full stack

```bash
docker compose up -d
```

### 3. Access the platform

| Service | URL |
|---|---|
| **Dashboard** | http://localhost:3000 |
| **API** | http://localhost:8000 |
| **API Docs** | http://localhost:8000/api/docs |
| **MinIO Console** | http://localhost:9001 |
| **OPA** | http://localhost:8181 |

### 4. Create your first user

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","full_name":"Admin","password":"Admin@12345!"}'
```

### 5. Trigger a compliance scan

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=admin@example.com&password=Admin@12345!" | jq -r .access_token)

# Register an AWS account
curl -X POST http://localhost:8000/api/v1/cloud-accounts/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Production AWS","provider":"aws","account_id":"123456789012","region":"us-east-1"}'

# Trigger scan
curl -X POST http://localhost:8000/api/v1/scans/trigger \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id":1,"framework":"all"}'
```

## 📋 Project Structure

```
CloudCompliancePlatform/
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── api/             # REST endpoints
│   │   ├── auth/            # JWT authentication
│   │   ├── connectors/      # AWS / Azure / GCP connectors
│   │   ├── core/            # CaC engine, scanner, ingestion, remediation
│   │   ├── ml/              # Anomaly detection (Isolation Forest)
│   │   ├── models/          # SQLAlchemy DB models
│   │   ├── schemas/         # Pydantic schemas
│   │   └── utils/           # Logger, crypto utilities
│   ├── policies/            # YAML compliance policy definitions
│   │   ├── pci_dss/
│   │   ├── hipaa/
│   │   ├── gdpr/
│   │   └── soc2/
│   └── tests/               # pytest unit + integration tests
├── frontend/                 # React 18 + Vite dashboard
├── opa/                      # Open Policy Agent Rego policies
├── .github/workflows/        # GitHub Actions CI/CD
└── docker-compose.yml        # Full stack orchestration
```

## 🔐 Security Standards

| Standard | Implementation |
|---|---|
| No hardcoded secrets | All credentials via ENV vars (Pydantic settings) |
| Auth | JWT (HS256) with short expiry + refresh tokens |
| Password storage | bcrypt with 12 rounds |
| HTTPS | TLS termination at Nginx reverse proxy |
| Input validation | Pydantic v2 on all API inputs |
| SQL injection | SQLAlchemy ORM only (no raw SQL) |
| Container hardening | Non-root user, read-only filesystem |
| Audit logging | Structured JSON logs for all actions |
| Evidence integrity | SHA-256 hash chains + HMAC signing |
| Dependency scanning | pip-audit in CI pipeline |

## 🧪 Running Tests

```bash
# Run unit tests inside the container
docker compose exec backend pytest tests/unit/ -v --cov=app

# Run with coverage threshold
docker compose exec backend pytest tests/ --cov=app --cov-fail-under=60
```

## ☁️ Cloud Provider Setup

### AWS
Set these in `.env`:
```
AWS_ACCESS_KEY_ID=AKIAXXXXXXXX
AWS_SECRET_ACCESS_KEY=xxxxxxxx
AWS_DEFAULT_REGION=us-east-1
# Optional: for cross-account role assumption
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/ComplianceRole
```

### Azure
```
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=xxxxxxxx
AZURE_SUBSCRIPTION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### GCP
```
GCP_PROJECT_ID=my-gcp-project
GCP_SERVICE_ACCOUNT_JSON_PATH=/app/secrets/service-account.json
```

## 📊 Supported Compliance Frameworks

| Framework | Version | Checks |
|---|---|---|
| PCI-DSS | v4.0 | 7 AWS resource policies |
| HIPAA | Security Rule | 6 AWS resource policies |
| GDPR | 2016/679 | 5 AWS resource policies |
| SOC 2 | Type II | 6 AWS resource policies |

## 🔄 CI/CD

GitHub Actions pipeline (`.github/workflows/ci.yml`) runs:
- ✅ `ruff` lint
- ✅ `mypy` type check
- ✅ `pip-audit` security scan
- ✅ `pytest` unit tests with coverage
- ✅ Frontend `npm build`
- ✅ Docker image build validation

## 📄 License

MIT License — © 2026 Cloud Compliance Platform
