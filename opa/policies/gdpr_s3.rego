# OPA Rego Policy GDPR S3 Checks
package compliance.gdpr.s3

import rego.v1

default allow := false

allow if {
    input.resource.encryption_enabled == true
    input.resource.public_access_blocked == true
    input.resource.versioning_enabled == true
}

deny contains reason if {
    not input.resource.encryption_enabled
    reason := "GDPR Art.32: Personal data storage must be encrypted failed"
}

deny contains reason if {
    not input.resource.public_access_blocked
    reason := "GDPR Art.32: Personal data must not be publicly accessible failed"
}

deny contains reason if {
    not input.resource.versioning_enabled
    reason := "GDPR Art.5: Enable data lifecycle management (versioning) failed"
}

