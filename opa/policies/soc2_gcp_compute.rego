# OPA Rego Policy SOC2 GCP_COMPUTE Checks
package compliance.soc2.gcp_compute

import rego.v1

default allow := false

allow if {
    input.resource.shielded_vm == true
}

deny contains reason if {
    not input.resource.shielded_vm
    reason := "SOC2 CC6.6: GCP Compute instances must be Shielded VMs failed"
}

