package compliance_framework.snapshot_or_dlm_backup_coverage

test_violation_without_completed_snapshot_or_dlm_coverage if {
    count(violation) == 1 with input as {
        "account_id": "123456789012",
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ],
            "Tags": [
                {"Key": "Backup", "Value": "required"},
                {"Key": "Application", "Value": "payments"}
            ]
        },
        "snapshots": [],
        "dlm_policies": []
    }
}

test_no_violation_with_completed_owned_snapshot_for_each_attached_volume if {
    count(violation) == 0 with input as {
        "account_id": "123456789012",
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}},
                {"DeviceName": "/dev/sdb", "Ebs": {"VolumeId": "vol-002"}}
            ],
            "Tags": [
                {"Key": "Backup", "Value": "required"},
                {"Key": "Application", "Value": "payments"}
            ]
        },
        "snapshots": [
            {"SnapshotId": "snap-001", "VolumeId": "vol-001", "State": "completed", "OwnerId": "123456789012"},
            {"SnapshotId": "snap-002", "VolumeId": "vol-002", "State": "completed", "OwnerId": "123456789012"}
        ],
        "dlm_policies": []
    }
}

test_no_violation_with_enabled_dlm_policy_with_retention_matching_instance_tags if {
    count(violation) == 0 with input as {
        "account_id": "123456789012",
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ],
            "Tags": [
                {"Key": "Backup", "Value": "required"},
                {"Key": "Application", "Value": "payments"}
            ]
        },
        "snapshots": [],
        "dlm_policies": [
            {
                "State": "ENABLED",
                "PolicyDetails": {
                    "TargetTags": [
                        {"Key": "Backup", "Value": "required"},
                        {"Key": "Application", "Value": "payments"}
                    ],
                    "Schedules": [
                        {"Name": "daily", "RetainRule": {"Count": 7}}
                    ]
                }
            }
        ]
    }
}
