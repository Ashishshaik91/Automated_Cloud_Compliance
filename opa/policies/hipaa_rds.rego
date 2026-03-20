# OPA Rego Policy HIPAA RDS Checks
package compliance.hipaa.rds

import rego.v1

default allow := false

allow if {
    input.resource.storage_encrypted == true
}

deny contains reason if {
    not input.resource.storage_encrypted
    reason := "HIPAA: Databases storing PHI must be encrypted failed"
}

