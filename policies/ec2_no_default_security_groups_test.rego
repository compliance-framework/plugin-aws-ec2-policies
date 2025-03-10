package compliance_framework.template.aws._deny_default_sg

test_violation_with_default_security_group if {
    violation[violation_item] with input as {
        "InstanceID": "i-0123456789abcdef0",
        "SecurityGroups": [
            {"GroupName": "default"}
        ]
    }

    violation_item.title == "EC2 instance is launched with the default security group"
}
