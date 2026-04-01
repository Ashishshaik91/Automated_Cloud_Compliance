# OPA Rego Policy SOC2 GCP_SQL Checks
package compliance.soc2.gcp_sql

import rego.v1

default allow := false

allow if {
    input.resource.backup_enabled == true
    input.resource.ip_configuration_require_ssl == true
}

deny contains reason if {
    not input.resource.ip_configuration_require_ssl
    reason := "SOC2 CC6.1: GCP Cloud SQL must enforce SSL/TLS connections failed"
}

deny contains reason if {
    not input.resource.backup_enabled
    reason := "SOC2 A1.2: GCP Cloud SQL must have automated backups enabled failed"
}

