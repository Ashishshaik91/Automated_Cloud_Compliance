# OPA Rego Policy CIS STORAGE Checks
package compliance.cis.storage

import rego.v1

default allow := false

allow if {
    input.resource.is_encrypted == true
}

deny contains reason if {
    not input.resource.is_encrypted
    reason := "Storage Account Encrypted failed"
}

