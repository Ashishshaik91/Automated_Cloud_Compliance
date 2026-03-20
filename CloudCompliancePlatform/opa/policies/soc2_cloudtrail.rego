# OPA Rego Policy SOC2 CLOUDTRAIL Checks
package compliance.soc2.cloudtrail

import rego.v1

default allow := false

allow if {
    input.resource.is_logging == true
}

deny contains reason if {
    not input.resource.is_logging
    reason := "SOC2 CC7.2: System monitoring must be enabled (CloudTrail) failed"
}

