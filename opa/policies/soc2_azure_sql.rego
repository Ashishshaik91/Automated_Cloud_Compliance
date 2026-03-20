# OPA Rego Policy SOC2 AZURE_SQL Checks
package compliance.soc2.azure_sql

import rego.v1

default allow := false

allow if {
    input.resource.public_network_access == false
}

deny contains reason if {
    input.resource.public_network_access
    reason := "SOC2 CC6.6: Azure SQL Server must not be publicly accessible failed"
}

