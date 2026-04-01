# OPA Rego Policy OWASP API_GATEWAY Checks
package compliance.owasp.api_gateway

import rego.v1

default allow := false

allow if {
    input.resource.waf_enabled == true
}

deny contains reason if {
    not input.resource.waf_enabled
    reason := "WAF Enabled for APIs (A1:2021) failed"
}

