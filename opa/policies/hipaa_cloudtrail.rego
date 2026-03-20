# OPA Rego Policy HIPAA CLOUDTRAIL Checks
package compliance.hipaa.cloudtrail

import rego.v1

default allow := false

allow if {
    input.resource.is_logging == true
}

deny contains reason if {
    not input.resource.is_logging
    reason := "HIPAA: Audit logging must be enabled (CloudTrail) failed"
}

