# OPA Rego Policy PCI_DSS IAM Checks
package compliance.pci_dss.iam

import rego.v1

default allow := false

allow if {
    input.resource.mfa_enabled == true
}

deny contains reason if {
    not input.resource.mfa_enabled
    reason := "PCI-DSS: IAM users must have MFA enabled failed"
}

