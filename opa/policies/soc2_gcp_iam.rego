# OPA Rego Policy SOC2 GCP_IAM Checks
package compliance.soc2.gcp_iam

import rego.v1

default allow := false

allow if {
    input.resource.has_public_bindings == false
}

deny contains reason if {
    input.resource.has_public_bindings
    reason := "SOC2 CC6.1: GCP Project IAM must not contain public bindings failed"
}

