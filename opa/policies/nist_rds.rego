# OPA Rego Policy NIST RDS Checks
package compliance.nist.rds

import rego.v1

default allow := false

allow if {
    input.resource.encryption_at_rest == true
}

deny contains reason if {
    not input.resource.encryption_at_rest
    reason := "Protection of Info at Rest (SC-28) failed"
}

