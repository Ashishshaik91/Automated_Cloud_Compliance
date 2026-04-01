# OPA Rego Policy OWASP LB Checks
package compliance.owasp.lb

import rego.v1

default allow := false

allow if {
    input.resource.tls_1_2_plus == true
}

deny contains reason if {
    not input.resource.tls_1_2_plus
    reason := "TLS 1.2+ Only (A2:2021) failed"
}

