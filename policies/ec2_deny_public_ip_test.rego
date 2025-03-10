package compliance_framework.template.aws._deny_public_ip

test_violation_with_public_ip if {
    count(violation) == 1 with input as {
        "InstanceID": "i-1234567890abcdef0",
        "PublicIP": "203.0.113.0"
    }
}

test_no_violation_without_public_ip if {
    count(violation) == 0 with input as {
        "InstanceID": "i-1234567890abcdef0",
        "PublicIP": ""
    }
}
