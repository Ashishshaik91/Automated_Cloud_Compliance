# OPA Rego Policy OWASP CLOUDTRAIL Checks
package compliance.owasp.cloudtrail

import rego.v1

default allow := false

allow if {
    input.resource.log_integrity_monitoring == true
}

deny contains reason if {
    not input.resource.log_integrity_monitoring
    reason := "Log Integrity Monitoring (A9:2021) failed"
}

