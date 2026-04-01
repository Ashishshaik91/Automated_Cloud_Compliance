# OPA Rego Policy NIST IAM Checks
package compliance.nist.iam

import rego.v1

default allow := false

allow if {
    input.resource.mfa_enabled == true
}

deny contains reason if {
    not input.resource.mfa_enabled
    reason := "Authenticator Management (IA-5) failed"
}

