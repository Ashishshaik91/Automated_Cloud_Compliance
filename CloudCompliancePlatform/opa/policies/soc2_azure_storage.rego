# OPA Rego Policy SOC2 AZURE_STORAGE Checks
package compliance.soc2.azure_storage

import rego.v1

default allow := false

allow if {
    input.resource.encryption_enabled == true
    input.resource.allow_blob_public_access == false
    input.resource.https_only == true
}

deny contains reason if {
    input.resource.allow_blob_public_access
    reason := "SOC2 CC6.7: Azure Storage accounts must not allow public access failed"
}

deny contains reason if {
    not input.resource.encryption_enabled
    reason := "SOC2 CC6.1: Azure Storage data at rest must be encrypted failed"
}

deny contains reason if {
    not input.resource.https_only
    reason := "SOC2 CC6.1: Azure Storage traffic must use HTTPS only failed"
}

