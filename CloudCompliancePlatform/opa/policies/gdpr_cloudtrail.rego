# OPA Rego Policy GDPR CLOUDTRAIL Checks
package compliance.gdpr.cloudtrail

import rego.v1

default allow := false

allow if {
    input.resource.is_logging == true
}

deny contains reason if {
    not input.resource.is_logging
    reason := "GDPR Art.30: Audit logging must be enabled for records of processing failed"
}

