package compliance_framework.template.aws._deny_missing_tags

test_violation_with_missing_tags if {
    count(violation) == 1 with input as {
        "InstanceID": "i-1234567890abcdef0",
        "Tags": [
            {"Key": "Name", "Value": "test-instance"},
            {"Key": "Environment", "Value": "prod"}
        ]
    }
}

test_no_violation_with_all_tags if {
    count(violation) == 0 with input as {
        "InstanceID": "i-1234567890abcdef0",
        "Tags": [
            {"Key": "Name", "Value": "test-instance"},
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Security", "Value": "high"},
            {"Key": "Compliance", "Value": "yes"},
            {"Key": "Application", "Value": "app1"},
            {"Key": "Cost Center", "Value": "cc1"},
            {"Key": "Project", "Value": "project1"},
            {"Key": "Owner", "Value": "owner1"}
        ]
    }
}
