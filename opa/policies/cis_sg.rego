# OPA Rego Policy CIS SG Checks
package compliance.cis.sg

import rego.v1

default allow := false

allow if {
    input.resource.ssh_open == false
}

deny contains reason if {
    input.resource.ssh_open
    reason := "No Open SSH to 0.0.0.0/0 failed"
}

