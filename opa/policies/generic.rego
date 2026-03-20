# OPA Rego Policy — Generic Compliance Rules
# Base rules applicable across all frameworks

package compliance.generic

import rego.v1

default allow := false

# A resource passes if no deny rules are triggered
allow if {
    count(deny) == 0
}

deny contains reason if {
    input.policy.rules[_].operator == "is_true"
    field := input.policy.rules[_].field
    not input.resource[field]
    reason := sprintf("Field '%v' must be true", [field])
}

deny contains reason if {
    input.policy.rules[_].operator == "is_false"
    field := input.policy.rules[_].field
    input.resource[field]
    reason := sprintf("Field '%v' must be false", [field])
}

deny contains reason if {
    input.policy.rules[_].operator == "equals"
    field := input.policy.rules[_].field
    value := input.policy.rules[_].value
    input.resource[field] != value
    reason := sprintf("Field '%v' must equal '%v'", [field, value])
}
