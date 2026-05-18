package compliance_framework.deny_default_sg

test_violation_with_default_security_group if {
    count(violation) == 1 with input as {
        "instance": {
            "InstanceId": "i-0123456789abcdef0",
            "SecurityGroups": [
                {"GroupName": "default"}
            ]
        }
    }
}

test_no_violation_with_non_default_security_group if {
    count(violation) == 0 with input as {
        "instance": {
            "InstanceId": "i-0123456789abcdef0",
            "SecurityGroups": [
                {"GroupName": "web-server-sg"}
            ]
        }
    }
}
