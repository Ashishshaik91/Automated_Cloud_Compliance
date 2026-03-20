# OPA Rego Policy GDPR RDS Checks
package compliance.gdpr.rds

import rego.v1

default allow := false

allow if {
    input.resource.storage_encrypted == true
}

deny contains reason if {
    not input.resource.storage_encrypted
    reason := "GDPR Art.32: Databases with personal data must be encrypted failed"
}

