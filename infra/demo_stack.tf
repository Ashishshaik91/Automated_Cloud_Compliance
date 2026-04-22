terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Generate a random ID to prevent bucket name collisions
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# ==========================================
# INTENTIONALLY VULNERABLE AWS RESOURCES
# ==========================================

# 1. Non-compliant S3 Bucket
# Violates: PCI-DSS, SOC 2, HIPAA, NIST, CIS (No encryption, public access allowed)
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "compliance-demo-bucket-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "vulnerable_bucket_public_access" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = var.apply_fixes
  block_public_policy     = var.apply_fixes
  ignore_public_acls      = var.apply_fixes
  restrict_public_buckets = var.apply_fixes
}

# 2. Non-compliant IAM User
# Violates: SOC 2, HIPAA, NIST (No MFA, stagnant active access keys)
resource "aws_iam_user" "vulnerable_user" {
  name          = "demo-unsecured-user"
  force_destroy = true
}
resource "aws_iam_access_key" "vulnerable_user_key" {
  user = aws_iam_user.vulnerable_user.name
}

# 3. Non-compliant EC2 Security Group
# Violates: PCI-DSS, SOC 2, CIS (Open SSH to World)
resource "aws_security_group" "vulnerable_sg" {
  name        = "demo-open-ssh"
  description = "Open SSH to the world"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
