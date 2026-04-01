# OPA Rego Policy NIST S3 Checks
package compliance.nist.s3

import rego.v1

default allow := false

allow if {
    input.resource.fips_validated == true
}

deny contains reason if {
    not input.resource.fips_validated
    reason := "FIPS Validated Crypto (SC-13) failed"
}

