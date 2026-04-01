# OPA Rego Policy SOC2 RDS Checks
package compliance.soc2.rds

import rego.v1

default allow := false

allow if {
    input.resource.publicly_accessible == false
    input.resource.multi_az == true
}

deny contains reason if {
    not input.resource.multi_az
    reason := "SOC2 A1.2: Databases must use Multi-AZ for high availability failed"
}

deny contains reason if {
    input.resource.publicly_accessible
    reason := "SOC2 CC6.6: Database instances must not be publicly accessible failed"
}

