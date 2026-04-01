# ======================================================================
# INTENTIONALLY VULNERABLE GCP RESOURCES FOR COMPLIANCE SCANNING
# ======================================================================
# Note: Ensure you run `terraform init` before `terraform apply`

provider "google" {
  # The GCP_PROJECT_ID from your .env file
  project = "compliance-reader" 
  region  = "us-central1"
  # This automatically uses the GOOGLE_APPLICATION_CREDENTIALS 
  # environment variable we will inject during deployment using your .json file
}

# Generate a random ID to prevent GCS bucket name collisions
resource "random_id" "gcp_bucket_suffix" {
  byte_length = 4
}

# 1. Non-compliant Google Cloud Storage (GCS) Bucket
# Violates: SOC 2, NIST, CIS (Uniform Bucket Level Access Disabled)
resource "google_storage_bucket" "vulnerable_gcs_bucket" {
  name                        = "compliance-demo-gcs-${random_id.gcp_bucket_suffix.hex}"
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = false
  public_access_prevention    = "inherited"
}

# 2. Non-compliant Compute Engine Instance
# Violates: GDPR, SOC 2, NIST, OWASP (No Shielded VM features enabled, Public IP assigned)
resource "google_compute_instance" "vulnerable_vm" {
  name         = "demo-unshielded-vm"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
    access_config {
      # Leaving this block empty automatically provisions an ephemeral Public IP
    }
  }

  shielded_instance_config {
    enable_secure_boot          = false
    enable_vtpm                 = false
    enable_integrity_monitoring = false
  }

  # Allow instance to be deleted even if it's running
  allow_stopping_for_update = true
}
