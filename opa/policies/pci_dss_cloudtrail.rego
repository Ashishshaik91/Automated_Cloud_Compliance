# OPA Rego Policy PCI_DSS CLOUDTRAIL Checks
package compliance.pci_dss.cloudtrail

import rego.v1

default allow := false

allow if {
    input.resource.is_logging == true
    input.resource.log_file_validation == true
}

deny contains reason if {
    not input.resource.is_logging
    reason := "PCI-DSS: CloudTrail logging must be enabled failed"
}

deny contains reason if {
    not input.resource.log_file_validation
    reason := "PCI-DSS: CloudTrail log file validation must be enabled failed"
}

