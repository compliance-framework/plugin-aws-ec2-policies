package compliance_framework.snapshot_restore_readiness

test_violation_without_completed_snapshot if {
    count(violation) == 1 with input as {
        "account_id": "123456789012",
        "instance": {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ],
            "Placement": {"AvailabilityZone": "eu-west-2a"}
        },
        "snapshots": []
    }
}

test_no_violation_with_completed_snapshot_when_fast_restore_not_required if {
    count(violation) == 0 with input as {
        "account_id": "123456789012",
        "instance": {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ],
            "Placement": {"AvailabilityZone": "eu-west-2a"}
        },
        "snapshots": [
            {"SnapshotId": "snap-001", "VolumeId": "vol-001", "State": "completed", "OwnerId": "123456789012"}
        ],
        "fast_snapshot_restores": []
    }
}

test_violation_when_fast_restore_required_but_not_enabled if {
    count(violation) == 1 with input as {
        "account_id": "123456789012",
        "instance": {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ],
            "Placement": {"AvailabilityZone": "eu-west-2a"}
        },
        "snapshots": [
            {"SnapshotId": "snap-001", "VolumeId": "vol-001", "State": "completed", "OwnerId": "123456789012"}
        ],
        "recovery_objective": {
            "requires_fast_snapshot_restore": true,
            "availability_zone": "eu-west-2a"
        },
        "fast_snapshot_restores": []
    }
}

test_no_violation_when_fast_restore_required_and_enabled_for_snapshot_in_zone if {
    count(violation) == 0 with input as {
        "account_id": "123456789012",
        "instance": {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ],
            "Placement": {"AvailabilityZone": "eu-west-2a"}
        },
        "snapshots": [
            {"SnapshotId": "snap-001", "VolumeId": "vol-001", "State": "completed", "OwnerId": "123456789012"}
        ],
        "recovery_objective": {
            "requires_fast_snapshot_restore": true,
            "availability_zone": "eu-west-2a"
        },
        "fast_snapshot_restores": [
            {"SnapshotId": "snap-001", "AvailabilityZone": "eu-west-2a", "State": "enabled"}
        ]
    }
}

test_violation_when_fast_restore_enabled_in_different_zone_than_required if {
    count(violation) == 1 with input as {
        "account_id": "123456789012",
        "instance": {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ],
            "Placement": {"AvailabilityZone": "eu-west-2a"}
        },
        "snapshots": [
            {"SnapshotId": "snap-001", "VolumeId": "vol-001", "State": "completed", "OwnerId": "123456789012"}
        ],
        "recovery_objective": {
            "requires_fast_snapshot_restore": true,
            "availability_zone": "eu-west-2a"
        },
        "fast_snapshot_restores": [
            {"SnapshotId": "snap-001", "AvailabilityZone": "eu-west-2b", "State": "enabled"}
        ]
    }
}

test_no_violation_when_fast_restore_required_zone_falls_back_to_instance_placement if {
    count(violation) == 0 with input as {
        "account_id": "123456789012",
        "instance": {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ],
            "Placement": {"AvailabilityZone": "eu-west-2a"}
        },
        "snapshots": [
            {"SnapshotId": "snap-001", "VolumeId": "vol-001", "State": "completed", "OwnerId": "123456789012"}
        ],
        "recovery_objective": {
            "requires_fast_snapshot_restore": true
        },
        "fast_snapshot_restores": [
            {"SnapshotId": "snap-001", "AvailabilityZone": "eu-west-2a", "State": "enabled"}
        ]
    }
}
