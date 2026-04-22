# ============================================================
#  compliance_fix.tf — Fix all vulnerable demo resources
#  to make them compliant. Applied alongside demo_stack.tf.
#
#  Usage (from infra/ directory):
#    terraform apply
#
#  After apply → Dashboard → click TRIGGER_SCAN
#  Score should rise as OPA re-evaluates compliant resources.
#
#  To restore vulnerability:
#    terraform destroy -target=aws_s3_bucket_server_side_encryption_configuration.fix_s3_encryption
#    ... (or full terraform destroy)
# ============================================================

# ─── Variables ────────────────────────────────────────────────────────────────

variable "bucket_name" {
  description = "Exact S3 bucket name (check AWS console). Updated automatically from demo_stack outputs."
  type        = string
  default     = "compliance-demo-bucket-a0bef97c"
}

variable "trail_name" {
  description = "CloudTrail trail name to enable logging on"
  type        = string
  default     = "TrailTesting"
}

variable "iam_user" {
  description = "IAM username with stale access keys to deactivate"
  type        = string
  default     = "demo-unsecured-user"
}

# ─── FIX 1: S3 — Enable AES-256 server-side encryption ───────────────────────
resource "aws_s3_bucket_server_side_encryption_configuration" "fix_s3_encryption" {
  bucket = var.bucket_name

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# ─── FIX 2: S3 — Block all public access ─────────────────────────────────────
# Overrides the vulnerable_bucket_public_access block in demo_stack.tf
resource "aws_s3_bucket_public_access_block" "fix_s3_public_access" {
  bucket = var.bucket_name

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket_server_side_encryption_configuration.fix_s3_encryption]
}

# ─── FIX 3: S3 — Enable versioning ───────────────────────────────────────────
resource "aws_s3_bucket_versioning" "fix_s3_versioning" {
  bucket = var.bucket_name

  versioning_configuration {
    status = "Enabled"
  }
}

# ─── FIX 4: Security Group — SSH restriction ─────────────────────────────────
# NOTE: The 'demo-open-ssh' Security Group no longer exists in AWS.
# The data source lookup is removed so `terraform destroy` does not fail
# attempting to refresh a resource that is already gone.

# ─── Outputs ──────────────────────────────────────────────────────────────────
output "compliance_fixes" {
  value = {
    "s3_encryption"    = "✅ AES-256 SSE enabled on ${var.bucket_name}"
    "s3_public_block"  = "✅ All public access blocked on ${var.bucket_name}"
    "s3_versioning"    = "✅ Versioning enabled on ${var.bucket_name}"
    "security_group"   = "⚠  demo-open-ssh SG no longer exists in AWS — already removed"
    "cloudtrail_note"  = "⚠  CloudTrail: run 'aws cloudtrail start-logging --name ${var.trail_name}' manually or use platform Execute"
    "iam_note"         = "⚠  IAM MFA: must be enabled manually via AWS console (MFA can't be provisioned by Terraform)"
  }
  description = "Summary of compliance remediations applied"
}

output "next_steps" {
  value = "Go to Dashboard → click TRIGGER_SCAN (top right) → score will update within 30s"
}

# --- FIX 4: IAM MFA Automation (Demo Mode) ----------------------------------
# Fully automates MFA by using pyotp and boto3 inside the backend container to
# generate virtual MFA tokens and bind them to the user.
resource "null_resource" "automate_mfa" {
  provisioner "local-exec" {
    command = "docker compose -f ../docker-compose.yml exec -T backend sh /app/secrets/run_mfa.sh"
  }
}
