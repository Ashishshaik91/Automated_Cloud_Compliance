# OPA Rego Policy SOC2 GCS Checks
package compliance.soc2.gcs

import rego.v1

default allow := false

allow if {
    input.resource.public_access_blocked == true
    input.resource.uniform_bucket_level_access == true
}

deny contains reason if {
    not input.resource.public_access_blocked
    reason := "SOC2 CC6.7: GCP Storage buckets must not allow public access failed"
}

deny contains reason if {
    not input.resource.uniform_bucket_level_access
    reason := "SOC2 CC6.1: GCP Storage must use Uniform Bucket-Level Access failed"
}

