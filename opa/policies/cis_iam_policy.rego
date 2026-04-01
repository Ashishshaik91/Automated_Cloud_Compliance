# OPA Rego Policy CIS IAM_POLICY Checks
package compliance.cis.iam_policy

import rego.v1

default allow := false

allow if {
    input.resource.strong_password == true
}

deny contains reason if {
    not input.resource.strong_password
    reason := "Strong Password Policy failed"
}

