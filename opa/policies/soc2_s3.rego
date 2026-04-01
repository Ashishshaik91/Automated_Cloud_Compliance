# OPA Rego Policy SOC2 S3 Checks
package compliance.soc2.s3

import rego.v1

default allow := false

allow if {
    input.resource.public_access_blocked == true
    input.resource.encryption_enabled == true
}

deny contains reason if {
    not input.resource.public_access_blocked
    reason := "SOC2 CC6.7: S3 buckets must not be publicly accessible failed"
}

deny contains reason if {
    not input.resource.encryption_enabled
    reason := "SOC2 CC6.1: Data at rest must be encrypted failed"
}

