# OPA Rego Policy — PCI-DSS S3 Checks
# Evaluates S3 bucket configurations against PCI-DSS requirements.

package compliance.pci_dss.s3

import rego.v1

# METADATA
# title: PCI-DSS S3 Compliance
# description: Enforces PCI-DSS encryption and access controls for S3 buckets

default allow := false

# Allow only if encryption AND public access blocked
allow if {
    input.resource.encryption_enabled == true
    input.resource.public_access_blocked == true
}

# Reasons for denial (for reporting)
deny contains reason if {
    not input.resource.encryption_enabled
    reason := "S3 bucket is not encrypted (PCI-DSS Req 3.5.1)"
}

deny contains reason if {
    not input.resource.public_access_blocked
    reason := "S3 bucket has public access enabled (PCI-DSS Req 1.3.2)"
}
