# OPA Rego Policy HIPAA S3 Checks
package compliance.hipaa.s3

import rego.v1

default allow := false

allow if {
    input.resource.public_access_blocked == true
    input.resource.versioning_enabled == true
    input.resource.encryption_enabled == true
}

deny contains reason if {
    not input.resource.encryption_enabled
    reason := "HIPAA: PHI storage (S3) must be encrypted at rest failed"
}

deny contains reason if {
    not input.resource.public_access_blocked
    reason := "HIPAA: S3 buckets with PHI must not be publicly accessible failed"
}

deny contains reason if {
    not input.resource.versioning_enabled
    reason := "HIPAA: S3 PHI storage must enable versioning for integrity failed"
}

