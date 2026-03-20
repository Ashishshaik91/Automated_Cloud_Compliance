# OPA Rego Policy SOC2 IAM Checks
package compliance.soc2.iam

import rego.v1

default allow := false

allow if {
    input.resource.mfa_enabled == true
}

deny contains reason if {
    not input.resource.mfa_enabled
    reason := "SOC2 CC6.1: MFA must be enabled for all user accounts failed"
}

