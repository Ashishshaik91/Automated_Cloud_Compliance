# OPA Rego Policy OWASP API_GATEWAY_CORS Checks
package compliance.owasp.api_gateway_cors

import rego.v1

default allow := false

allow if {
    input.resource.cors_restrictive == true
}

deny contains reason if {
    not input.resource.cors_restrictive
    reason := "Restrictive CORS (A5:2021) failed"
}

