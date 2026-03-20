# OPA Rego Policy PCI_DSS RDS Checks
package compliance.pci_dss.rds

import rego.v1

default allow := false

allow if {
    input.resource.storage_encrypted == true
    input.resource.publicly_accessible == false
}

deny contains reason if {
    not input.resource.storage_encrypted
    reason := "PCI-DSS: RDS instances must have storage encryption enabled failed"
}

deny contains reason if {
    input.resource.publicly_accessible
    reason := "PCI-DSS: RDS instances must not be publicly accessible failed"
}

