###############################################################################
# DSPM GCP Seed Data — Fake PII/PCI/PHI GCS buckets for DSPM scanner testing
#
# Uses the existing GCP provider from demo_stack_gcp.tf (project: compliance-reader)
# Creates GCS buckets with names that trigger the DSPM classification rules.
###############################################################################

# ─────────────────────────────────────────────────────────────────────────────
# 1. PII Production GCS Bucket (critical — name has "pii" + "prod")
# ─────────────────────────────────────────────────────────────────────────────
resource "google_storage_bucket" "gcs_pii_prod" {
  name                        = "pii-prod-user-data-${random_id.gcp_bucket_suffix.hex}"
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  labels = {
    classification = "pii"
    sensitivity    = "critical"
    dspm-seed      = "true"
    environment    = "production"
  }
}

resource "google_storage_bucket_object" "gcs_pii_customers" {
  name    = "customers/eu_customers_2024.csv"
  bucket  = google_storage_bucket.gcs_pii_prod.name
  content = <<-CSV
    id,name,email,national_id,phone
    1,Klaus Weber,k.weber@example.de,DE123456789,+4917612345678
    2,Marie Curie,m.curie@example.fr,FR987654321,+33612345678
    3,Giovanni Rossi,g.rossi@example.it,IT567890123,+39312345678
  CSV
  content_type = "text/csv"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. PCI Payments GCS Bucket (critical — name has "pci" + "payment")
# ─────────────────────────────────────────────────────────────────────────────
resource "google_storage_bucket" "gcs_pci_payments" {
  name                        = "pci-payment-logs-${random_id.gcp_bucket_suffix.hex}"
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  labels = {
    classification = "pci"
    sensitivity    = "critical"
    dspm-seed      = "true"
  }
}

resource "google_storage_bucket_object" "gcs_pci_txns" {
  name    = "transactions/payment_log_q1_2024.json"
  bucket  = google_storage_bucket.gcs_pci_payments.name
  content = jsonencode([
    { txn_id = "GCP-TXN-001", card_last4 = "9999", amount = 2500.00, timestamp = "2024-01-10T09:00:00Z" },
    { txn_id = "GCP-TXN-002", card_last4 = "1234", amount = 175.50,  timestamp = "2024-01-10T10:15:00Z" },
  ])
  content_type = "application/json"
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. PHI Medical GCS Bucket (high sensitivity — name has "phi" + "medical")
# ─────────────────────────────────────────────────────────────────────────────
resource "google_storage_bucket" "gcs_phi_medical" {
  name                        = "phi-medical-imaging-${random_id.gcp_bucket_suffix.hex}"
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  labels = {
    classification = "phi"
    sensitivity    = "high"
    dspm-seed      = "true"
  }
}

resource "google_storage_bucket_object" "gcs_phi_records" {
  name    = "imaging/patient_metadata.json"
  bucket  = google_storage_bucket.gcs_phi_medical.name
  content = jsonencode([
    { patient_id = "GCP-P001", study_type = "MRI", dob = "1970-06-15", referring_physician = "Dr. Smith" },
    { patient_id = "GCP-P002", study_type = "CT",  dob = "1985-11-30", referring_physician = "Dr. Jones" },
  ])
  content_type = "application/json"
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. GDPR EU Privacy GCS Bucket (high sensitivity — name has "gdpr" + "privacy")
# ─────────────────────────────────────────────────────────────────────────────
resource "google_storage_bucket" "gcs_gdpr_eu" {
  name                        = "gdpr-privacy-eu-records-${random_id.gcp_bucket_suffix.hex}"
  location                    = "EUROPE-WEST1"
  force_destroy               = true
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  labels = {
    classification = "gdpr"
    sensitivity    = "high"
    dspm-seed      = "true"
    region         = "eu"
  }
}

resource "google_storage_bucket_object" "gcs_gdpr_consent" {
  name    = "consent/gdpr_consent_records_2024.csv"
  bucket  = google_storage_bucket.gcs_gdpr_eu.name
  content = <<-CSV
    user_id,email,consent_given,consent_date,data_categories
    G001,user1@example.eu,true,2024-01-01,"marketing,analytics"
    G002,user2@example.eu,false,2024-01-02,"essential"
  CSV
  content_type = "text/csv"
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. CRITICAL: Publicly-exposed legacy GCS bucket
#    (public_access_prevention=inherited → public ACLs possible)
# ─────────────────────────────────────────────────────────────────────────────
resource "google_storage_bucket" "gcs_exposed_legacy" {
  name                        = "pii-exposed-legacy-backup-${random_id.gcp_bucket_suffix.hex}"
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = false  # legacy ACLs enabled
  public_access_prevention    = "inherited"  # may allow public access

  labels = {
    classification = "pii"
    sensitivity    = "critical"
    dspm-seed      = "true"
    note           = "legacy-exposed"
  }
}

resource "google_storage_bucket_object" "gcs_exposed_dump" {
  name    = "export/legacy_user_dump.csv"
  bucket  = google_storage_bucket.gcs_exposed_legacy.name
  content = <<-CSV
    id,username,email,password_hash
    9001,legacyuser1,legacy1@example.com,5f4dcc3b5aa765d61d8327deb882cf99
  CSV
  content_type = "text/csv"
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. Dev/test GCS Bucket (low sensitivity)
# ─────────────────────────────────────────────────────────────────────────────
resource "google_storage_bucket" "gcs_dev_test" {
  name                        = "dev-test-gcp-synthetic-${random_id.gcp_bucket_suffix.hex}"
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  labels = {
    classification = "unknown"
    sensitivity    = "low"
    dspm-seed      = "true"
    environment    = "development"
  }
}

resource "google_storage_bucket_object" "gcs_dev_seed" {
  name         = "seed/synthetic_test_records.json"
  bucket       = google_storage_bucket.gcs_dev_test.name
  content      = jsonencode({ note = "GCP synthetic test data only. No real PII.", generated = "2024-01-01" })
  content_type = "application/json"
}

# ─────────────────────────────────────────────────────────────────────────────
# Outputs
# ─────────────────────────────────────────────────────────────────────────────
output "gcp_dspm_seed_buckets" {
  description = "GCP DSPM seed GCS buckets created for scanner testing"
  value = {
    pii_prod      = google_storage_bucket.gcs_pii_prod.name
    pci_payments  = google_storage_bucket.gcs_pci_payments.name
    phi_medical   = google_storage_bucket.gcs_phi_medical.name
    gdpr_eu       = google_storage_bucket.gcs_gdpr_eu.name
    exposed_pii   = google_storage_bucket.gcs_exposed_legacy.name
    dev_test      = google_storage_bucket.gcs_dev_test.name
  }
}
