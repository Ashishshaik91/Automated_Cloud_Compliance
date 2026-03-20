# OPA Rego Policy HIPAA IAM Checks
package compliance.hipaa.iam

import rego.v1

default allow := false

allow if {
    input.resource.mfa_enabled == true
}

deny contains reason if {
    not input.resource.mfa_enabled
    reason := "HIPAA: MFA required for all user access failed"
}

