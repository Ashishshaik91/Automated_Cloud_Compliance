###############################################################################
# GCP VIOLATIONS STACK — Intentionally Non-Compliant Resources
#
# Targets violation rules:
#   GCP-GCS-001  — GCS bucket with uniform bucket-level access DISABLED
#   GCP-FW-001   — Firewall rule allowing all ingress from 0.0.0.0/0
#   GCP-SA-001   — Service account with user-managed key (stale)
#   GCP-LOG-001  — Audit logs not enabled (project-level)
#   gcp-compute-ip-forward  — VM with IP forwarding enabled, no shielded VM
#   gcp-sql-require-ssl     — Cloud SQL with SSL disabled (commented out, ~10 min)
#
# Uses provider from demo_stack_gcp.tf (project: compliance-reader, us-central1)
# Random suffix from random_id.gcp_bucket_suffix already declared there.
###############################################################################

# ─────────────────────────────────────────────────────────────────────────────
# 1. GCS Bucket — Public Access Not Enforced  [GCP-GCS-001 / gcp-gcs-no-public-access]
#    NOTE: GCP Org Policy enforces uniformBucketLevelAccess=true on this project,
#    so we cannot disable it. The compliance violation is triggered instead by
#    public_access_prevention = "inherited" (vs the secure value "enforced").
#    The scanner flags: public_access_blocked = false.
# ─────────────────────────────────────────────────────────────────────────────
resource "google_storage_bucket" "vuln_gcs_public_access" {
  name                        = "vuln-public-access-${random_id.gcp_bucket_suffix.hex}"
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = true         # required by org policy
  public_access_prevention    = "inherited"  # VIOLATION: not explicitly enforced

  labels = {
    violation  = "gcp-gcs-001"
    managed-by = "compliance-demo"
  }
}

resource "google_storage_bucket_object" "vuln_gcs_readme" {
  name    = "README.txt"
  bucket  = google_storage_bucket.vuln_gcs_public_access.name
  content = "This bucket has public_access_prevention=inherited for compliance testing."
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. Firewall Rule — All Ingress Allowed  [GCP-FW-001]
#    Allows ALL protocols from 0.0.0.0/0 — maximum exposure
# ─────────────────────────────────────────────────────────────────────────────
resource "google_compute_firewall" "vuln_fw_all_ingress" {
  name    = "vuln-allow-all-ingress"
  network = "default"

  allow {
    protocol = "all"  # VIOLATION: all protocols
  }

  source_ranges = ["0.0.0.0/0"]  # VIOLATION: any IP
  direction     = "INGRESS"

  target_tags = ["vuln-demo"]

  description = "INTENTIONALLY VULNERABLE: allows all ingress. For compliance testing only."

  log_config {
    metadata = "EXCLUDE_ALL_METADATA"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. Service Account + User-Managed Key  [GCP-SA-001]
#    NOTE: Requires the IAM API to be enabled in project compliance-reader.
#    Enable at: https://console.cloud.google.com/apis/api/iam.googleapis.com
#    Uncomment below once the API is enabled.
# ─────────────────────────────────────────────────────────────────────────────

# resource "google_service_account" "vuln_demo_sa" {
#   account_id   = "vuln-demo-compliance-sa"
#   display_name = "Vulnerable Demo SA (compliance testing)"
#   description  = "Service account with an unrotated user-managed key"
# }
#
# resource "google_service_account_key" "vuln_sa_key" {
#   service_account_id = google_service_account.vuln_demo_sa.name
#   public_key_type    = "TYPE_X509_PEM_FILE"
# }

# ─────────────────────────────────────────────────────────────────────────────
# 4. IAM Audit Config — Disabled  [GCP-LOG-001]
#    Removes audit logging for storage and compute — most restrictive violation
# ─────────────────────────────────────────────────────────────────────────────
# NOTE: Disabling audit logs at the project level requires the
# resourcemanager.projects.setIamPolicy permission on the project.
# If this fails, comment it out — the scanner seeds it via ComplianceCheck seeder.

# resource "google_project_iam_audit_config" "vuln_no_audit" {
#   project = "compliance-reader"
#   service = "storage.googleapis.com"
#   audit_log_config {
#     log_type = "DATA_READ"
#     # exempted_members intentionally left to disable audit
#   }
# }

# Instead we rely on the GCP Logging connector enumeration to detect
# that DATA_WRITE / DATA_READ audit logs are not configured for critical services.
# The scanner seeds a ComplianceCheck fail row when audit log config is absent.

# ─────────────────────────────────────────────────────────────────────────────
# 5. Compute Instance — IP Forwarding + No Shielded VM  [gcp-compute-ip-forward]
#    can_ip_forward = true → instance can route traffic (MITM risk)
#    shielded_vm disabled → no secure boot, vTPM, or integrity monitoring
# ─────────────────────────────────────────────────────────────────────────────
resource "google_compute_instance" "vuln_ip_forward_vm" {
  name         = "vuln-ip-forward-vm"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  can_ip_forward = true  # VIOLATION: packet routing enabled

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
    access_config {}  # ephemeral public IP
  }

  shielded_instance_config {
    enable_secure_boot          = false  # VIOLATION: no secure boot
    enable_vtpm                 = false  # VIOLATION: no vTPM
    enable_integrity_monitoring = false  # VIOLATION: no integrity monitoring
  }

  allow_stopping_for_update = true

  metadata = {
    violation  = "gcp-compute-ip-forward"
    managed-by = "compliance-demo"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. Cloud SQL — SSL Disabled + Backup Disabled  [gcp-sql-require-ssl]
#    COMMENTED OUT BY DEFAULT: takes ~8-10 min to provision + hourly cost.
#    Uncomment to enable Cloud SQL compliance testing.
# ─────────────────────────────────────────────────────────────────────────────

# resource "google_sql_database_instance" "vuln_sql_no_ssl" {
#   name             = "vuln-sql-no-ssl-${random_id.gcp_bucket_suffix.hex}"
#   database_version = "MYSQL_8_0"
#   region           = "us-central1"
#   deletion_protection = false
#
#   settings {
#     tier = "db-f1-micro"
#
#     ip_configuration {
#       require_ssl             = false  # VIOLATION: plaintext connections allowed
#       ipv4_enabled            = true
#       authorized_networks {
#         name  = "all"
#         value = "0.0.0.0/0"  # VIOLATION: publicly accessible
#       }
#     }
#
#     backup_configuration {
#       enabled = false  # VIOLATION: no automated backups
#     }
#   }
# }

# ─────────────────────────────────────────────────────────────────────────────
# Outputs
# ─────────────────────────────────────────────────────────────────────────────
output "gcp_violation_resources" {
  description = "GCP non-compliant resources created for violations scanner testing"
  value = {
    gcs_public_access_bucket = google_storage_bucket.vuln_gcs_public_access.name
    firewall_all_ingress      = google_compute_firewall.vuln_fw_all_ingress.name
    ip_forward_vm             = google_compute_instance.vuln_ip_forward_vm.name
    sa_note                   = "Enable IAM API to also deploy service account key (GCP-SA-001)"
  }
}
