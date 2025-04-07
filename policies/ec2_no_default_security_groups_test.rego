package compliance_framework.deny_default_sg

test_violation_with_default_security_group if {
    count(violation) == 1 with input as {
        "InstanceID": "i-0123456789abcdef0",
        "SecurityGroups": [
            {"GroupName": "default"}
        ]
    }
}
