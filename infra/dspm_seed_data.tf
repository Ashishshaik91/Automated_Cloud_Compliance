###############################################################################
# DSPM Seed Data — Fake PII/PCI/PHI data stores for DSPM scanner testing
#
# Creates realistic S3 buckets + objects with names and tags that the DSPM
# engine classifies as PII, PCI, PHI, GDPR-sensitive data.
# Also creates an unencrypted public bucket to trigger critical risk scores.
###############################################################################

resource "random_id" "dspm_suffix" {
  byte_length = 3
}

locals {
  sfx = random_id.dspm_suffix.hex
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. PII Production Bucket (critical sensitivity — name contains "pii" + "prod")
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "pii_prod" {
  bucket        = "pii-prod-customers-${local.sfx}"
  force_destroy = true
  tags = {
    Classification = "PII"
    Sensitivity    = "critical"
    Environment    = "production"
    Owner          = "data-team"
    DSPMSeed       = "true"
  }
}

# Block public access (good practice — but DSPM still classifies as critical)
resource "aws_s3_bucket_public_access_block" "pii_prod_block" {
  bucket                  = aws_s3_bucket.pii_prod.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "pii_prod_enc" {
  bucket = aws_s3_bucket.pii_prod.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Seed fake PII CSV records
resource "aws_s3_object" "pii_customers" {
  bucket       = aws_s3_bucket.pii_prod.id
  key          = "customers/customer_records_2024.csv"
  content_type = "text/csv"
  content      = <<-CSV
    id,name,email,ssn,credit_card,dob
    1,John Smith,john.smith@example.com,123-45-6789,4111111111111111,1985-03-15
    2,Jane Doe,jane.doe@example.com,987-65-4321,5500005555555559,1990-07-22
    3,Alice Johnson,alice.j@example.com,555-12-3456,378282246310005,1978-11-08
  CSV
  tags = { Classification = "PII-PCI", Sensitivity = "critical" }
}

resource "aws_s3_object" "pii_employees" {
  bucket       = aws_s3_bucket.pii_prod.id
  key          = "hr/employee_data_2024.csv"
  content_type = "text/csv"
  content      = <<-CSV
    employee_id,full_name,national_id,salary,bank_account
    E001,Michael Chen,A12345678,95000,GB29NWBK60161331926819
    E002,Sarah Williams,B98765432,112000,DE89370400440532013000
  CSV
  tags = { Classification = "PII", Sensitivity = "critical" }
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. PCI Payment Data Bucket (critical — name contains "pci")
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "pci_payments" {
  bucket        = "pci-payments-archive-${local.sfx}"
  force_destroy = true
  tags = {
    Classification = "PCI"
    Sensitivity    = "critical"
    Environment    = "production"
    Owner          = "finance-team"
    DSPMSeed       = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "pci_block" {
  bucket                  = aws_s3_bucket.pci_payments.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "pci_enc" {
  bucket = aws_s3_bucket.pci_payments.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "pci_transactions" {
  bucket       = aws_s3_bucket.pci_payments.id
  key          = "transactions/txn_log_2024_q1.json"
  content_type = "application/json"
  content      = jsonencode([
    { txn_id = "TXN-001", card_last4 = "4242", amount = 1500.00, merchant = "ACME Corp", timestamp = "2024-01-15T10:30:00Z" },
    { txn_id = "TXN-002", card_last4 = "1111", amount = 299.99,  merchant = "TechStore",  timestamp = "2024-01-15T11:00:00Z" },
  ])
  tags = { Classification = "PCI", Sensitivity = "critical" }
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. PHI Medical Records Bucket (high sensitivity — name contains "phi"/"med")
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "phi_medical" {
  bucket        = "phi-medical-records-${local.sfx}"
  force_destroy = true
  tags = {
    Classification = "PHI-HIPAA"
    Sensitivity    = "high"
    Environment    = "production"
    Owner          = "medical-team"
    DSPMSeed       = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "phi_block" {
  bucket                  = aws_s3_bucket.phi_medical.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "phi_records" {
  bucket       = aws_s3_bucket.phi_medical.id
  key          = "records/patient_records_batch_01.json"
  content_type = "application/json"
  content      = jsonencode([
    { patient_id = "P-001", diagnosis_code = "J18.9", dob = "1965-04-22", insurance_id = "INS-12345" },
    { patient_id = "P-002", diagnosis_code = "E11.9", dob = "1978-09-10", insurance_id = "INS-67890" },
  ])
  tags = { Classification = "PHI-HIPAA", Sensitivity = "high" }
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. GDPR EU Data Bucket (high sensitivity)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "gdpr_eu" {
  bucket        = "gdpr-eu-user-data-${local.sfx}"
  force_destroy = true
  tags = {
    Classification = "GDPR-PII"
    Sensitivity    = "high"
    Environment    = "production"
    Region         = "eu-west-1"
    Owner          = "eu-data-team"
    DSPMSeed       = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "gdpr_block" {
  bucket                  = aws_s3_bucket.gdpr_eu.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "gdpr_users" {
  bucket       = aws_s3_bucket.gdpr_eu.id
  key          = "users/eu_user_export_2024.csv"
  content_type = "text/csv"
  content      = <<-CSV
    user_id,email,country,consent_date,ip_address
    U001,hans.mueller@example.de,DE,2024-01-10,192.168.1.100
    U002,marie.dupont@example.fr,FR,2024-01-12,10.0.0.50
  CSV
  tags = { Classification = "GDPR-PII", Sensitivity = "high" }
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. CRITICAL: Unencrypted PUBLIC bucket — highest DSPM risk score
#    (public_access=true + encryption=none + sensitivity=critical)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "exposed_pii" {
  bucket        = "pii-exposed-backup-${local.sfx}"
  force_destroy = true
  tags = {
    Classification = "PII-PCI"
    Sensitivity    = "critical"
    Environment    = "legacy"
    Owner          = "unknown"
    DSPMSeed       = "true"
    RiskNote       = "EXPOSED-NO-ENCRYPTION"
  }
}

# Explicitly allow public access (triggers DSPM critical + public multiplier)
resource "aws_s3_bucket_public_access_block" "exposed_block" {
  bucket                  = aws_s3_bucket.exposed_pii.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_object" "exposed_dump" {
  bucket       = aws_s3_bucket.exposed_pii.id
  key          = "dump/legacy_users.csv"
  content_type = "text/csv"
  content      = <<-CSV
    id,name,email,ssn
    9001,Legacy User,legacy@example.com,000-00-0001
  CSV
  tags = { Classification = "PII", Sensitivity = "critical" }
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. Dev/Test bucket (low sensitivity — name contains "dev")
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "dev_test" {
  bucket        = "dev-test-synthetic-data-${local.sfx}"
  force_destroy = true
  tags = {
    Classification = "UNKNOWN"
    Sensitivity    = "low"
    Environment    = "development"
    Owner          = "dev-team"
    DSPMSeed       = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "dev_block" {
  bucket                  = aws_s3_bucket.dev_test.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "dev_seed" {
  bucket       = aws_s3_bucket.dev_test.id
  key          = "seed/synthetic_test_data.json"
  content_type = "application/json"
  content      = jsonencode({ note = "This is synthetic test data only. No real PII.", generated = "2024-01-01" })
  tags = { Classification = "UNKNOWN", Sensitivity = "low" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Outputs
# ─────────────────────────────────────────────────────────────────────────────
output "dspm_seed_buckets" {
  description = "DSPM seed S3 buckets created for scanner testing"
  value = {
    pii_prod      = aws_s3_bucket.pii_prod.bucket
    pci_payments  = aws_s3_bucket.pci_payments.bucket
    phi_medical   = aws_s3_bucket.phi_medical.bucket
    gdpr_eu       = aws_s3_bucket.gdpr_eu.bucket
    exposed_pii   = aws_s3_bucket.exposed_pii.bucket
    dev_test      = aws_s3_bucket.dev_test.bucket
  }
}
