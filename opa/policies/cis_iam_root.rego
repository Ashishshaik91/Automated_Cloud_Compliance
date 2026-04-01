# OPA Rego Policy CIS IAM_ROOT Checks
package compliance.cis.iam_root

import rego.v1

default allow := false

allow if {
    input.resource.mfa_enabled == true
}

deny contains reason if {
    not input.resource.mfa_enabled
    reason := "Avoid Root usage & ensure MFA failed"
}

