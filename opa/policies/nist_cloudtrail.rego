# OPA Rego Policy NIST CLOUDTRAIL Checks
package compliance.nist.cloudtrail

import rego.v1

default allow := false

allow if {
    input.resource.audit_logging_enabled == true
}

deny contains reason if {
    not input.resource.audit_logging_enabled
    reason := "Audit Logging Enabled (AU-2) failed"
}

