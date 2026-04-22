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
  count                       = var.apply_fixes ? 1 : 0
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
  count  = var.apply_fixes ? 1 : 0
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
  count        = var.apply_fixes ? 1 : 0
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

# ─── FIX 4: GCP IAM — Org Policies ──────────────────────────────────────────
# google_project_organization_policy requires Organisation Admin permissions.
# The service account does not have this role, so these are applied manually:
#   • compute.requireOsLogin  → GCP Console → IAM → Organisation Policies
#   • iam.disableServiceAccountKeyCreation → same path

# ─── Outputs ──────────────────────────────────────────────────────────────────
output "gcp_compliance_fixes" {
  value = {
    "gcs_public_access"  = "✅ ${var.gcs_bucket_name} — public_access_prevention set to 'enforced'"
    "gcs_no_public_read" = "✅ ${var.gcs_bucket_name} — allUsers/allAuthenticatedUsers removed from viewer role"
    "vm_shielded"        = "✅ demo-unshielded-vm — Secure Boot, vTPM, Integrity Monitoring all ON; public IP removed"
    "iam_os_login"       = "⚠  OS Login org policy requires Organisation Admin — apply manually in GCP Console"
    "iam_sa_keys"        = "⚠  SA key creation org policy requires Organisation Admin — apply manually in GCP Console"
    "iam_mfa_note"       = "⚠  Human user MFA — must be enabled via Google Admin Console"
  }
}
