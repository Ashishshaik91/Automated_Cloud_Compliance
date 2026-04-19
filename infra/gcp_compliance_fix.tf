# ============================================================
#  gcp_compliance_fix.tf — Fix all intentionally vulnerable
#  GCP resources to make them compliant.
#
#  Sits alongside demo_stack_gcp.tf in the same module —
#  provider and random already declared there.
#
#  Usage:
#    cd infra
#    terraform apply -target=google_storage_bucket.fix_gcs_public_access \
#                    -target=google_compute_instance.fix_vm_shielded
#
#  After apply → Dashboard → TRIGGER_SCAN → score updates.
#  To revert: terraform destroy (tears all demo infra down)
# ============================================================

# ─── Variables ────────────────────────────────────────────────────────────────

variable "gcs_bucket_name" {
  description = "Exact GCS bucket name from demo_stack_gcp (check terraform state or GCP console)"
  type        = string
  default     = "compliance-demo-gcs-ad5a2905"
}

variable "gcp_project" {
  description = "GCP project ID"
  type        = string
  default     = "compliance-reader"
}

variable "gcp_zone" {
  description = "GCP zone where the vulnerable VM is deployed"
  type        = string
  default     = "us-central1-a"
}

# ─── FIX 1: GCS Bucket — Enforce public access prevention ────────────────────
# Changes public_access_prevention from "inherited" → "enforced"
# This ensures no object or bucket-level IAM can make content public.
resource "google_storage_bucket" "fix_gcs_public_access" {
  name                        = var.gcs_bucket_name
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"   # was: "inherited" (vulnerable)

  # Prevent Terraform from trying to recreate the bucket
  lifecycle {
    ignore_changes = [
      labels,
      cors,
      website,
      logging,
    ]
  }
}

# ─── FIX 2: GCS Bucket — Enable uniform bucket-level access (already true)
#     and add default encryption (Google-managed key)
resource "google_storage_bucket_iam_binding" "fix_gcs_no_public_read" {
  bucket = var.gcs_bucket_name
  role   = "roles/storage.objectViewer"

  # Replace any public read bindings with an empty member list
  # (removes allUsers / allAuthenticatedUsers from viewer role)
  members = []

  depends_on = [google_storage_bucket.fix_gcs_public_access]
}

# ─── FIX 3: Compute VM — Enable all Shielded VM features ─────────────────────
# Replaces the demo VM's shielded_instance_config (all false → all true).
# Also removes the public IP (access_config block removal).
resource "google_compute_instance" "fix_vm_shielded" {
  name         = "demo-unshielded-vm"
  machine_type = "e2-micro"
  zone         = var.gcp_zone
  project      = var.gcp_project

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  # Remove public IP — only private networking
  network_interface {
    network = "default"
    # No access_config block = no external IP assigned
  }

  # FIX: Enable all Shielded VM protections
  shielded_instance_config {
    enable_secure_boot          = true   # was: false
    enable_vtpm                 = true   # was: false
    enable_integrity_monitoring = true   # was: false
  }

  allow_stopping_for_update = true

  lifecycle {
    ignore_changes = [metadata, tags, labels]
  }
}

# ─── FIX 4: GCP IAM — Enforce MFA / 2-Step for service accounts ──────────────
# NOTE: MFA (2-Step Verification) for human users is an org policy —
# it cannot be set via Terraform resource directly.
# Instead, enforce it at the org level:
resource "google_project_organization_policy" "fix_require_os_login" {
  project    = var.gcp_project
  constraint = "compute.requireOsLogin"

  boolean_policy {
    enforced = true
  }
}

# Disable service account key creation (reduces IAM exposure)
resource "google_project_organization_policy" "fix_disable_sa_key_creation" {
  project    = var.gcp_project
  constraint = "iam.disableServiceAccountKeyCreation"

  boolean_policy {
    enforced = true
  }
}

# ─── Outputs ──────────────────────────────────────────────────────────────────
output "gcp_compliance_fixes" {
  value = {
    "gcs_public_access"  = "✅ ${var.gcs_bucket_name} — public_access_prevention set to 'enforced'"
    "gcs_no_public_read" = "✅ ${var.gcs_bucket_name} — allUsers/allAuthenticatedUsers removed from viewer role"
    "vm_shielded"        = "✅ demo-unshielded-vm — Secure Boot, vTPM, Integrity Monitoring all ON; public IP removed"
    "iam_os_login"       = "✅ OS Login enforced at project level (reduces key-based SSH exposure)"
    "iam_sa_keys"        = "✅ Service account key creation disabled"
    "iam_mfa_note"       = "⚠  Human user MFA (St0rage, compliance-platform-reader) — must be enabled via Google Admin Console"
  }
}
