package compliance_framework.snapshot_restore_access_scope

test_violation_when_attached_volume_inventory_does_not_resolve_to_instance if {
    count(violation) == 1 with input as {
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ]
        },
        "volumes": [
            {
                "VolumeId": "vol-001",
                "Attachments": [
                    {"InstanceId": "i-other"}
                ]
            }
        ],
        "snapshot_inventory": [
            {
                "snapshot_id": "snap-001",
                "volume_id": "vol-001",
                "state": "completed",
                "public_share_enabled": false
            }
        ],
        "snapshot_permissions": []
    }
}

test_violation_when_in_scope_snapshot_is_public if {
    count(violation) == 1 with input as {
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ]
        },
        "volumes": [
            {
                "VolumeId": "vol-001",
                "Attachments": [
                    {"InstanceId": "i-1234567890abcdef0"}
                ]
            }
        ],
        "snapshot_inventory": [
            {
                "snapshot_id": "snap-001",
                "volume_id": "vol-001",
                "state": "completed",
                "public_share_enabled": true
            }
        ],
        "snapshot_permissions": []
    }
}

test_no_violation_when_snapshot_permissions_are_not_public if {
    count(violation) == 0 with input as {
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ]
        },
        "volumes": [
            {
                "VolumeId": "vol-001",
                "Attachments": [
                    {"InstanceId": "i-1234567890abcdef0"}
                ]
            }
        ],
        "snapshot_inventory": [
            {
                "snapshot_id": "snap-001",
                "volume_id": "vol-001",
                "state": "completed",
                "public_share_enabled": false
            }
        ],
        "snapshot_permissions": [
            {
                "snapshot_id": "snap-001",
                "public_share_enabled": false,
                "shared_account_ids": ["111122223333"]
            }
        ]
    }
}

test_violation_when_snapshot_permissions_public_share_enabled if {
    count(violation) == 1 with input as {
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ]
        },
        "volumes": [
            {
                "VolumeId": "vol-001",
                "Attachments": [
                    {"InstanceId": "i-1234567890abcdef0"}
                ]
            }
        ],
        "snapshot_inventory": [
            {
                "snapshot_id": "snap-001",
                "volume_id": "vol-001",
                "state": "completed",
                "public_share_enabled": false
            }
        ],
        "snapshot_permissions": [
            {
                "snapshot_id": "snap-001",
                "public_share_enabled": true
            }
        ]
    }
}

test_violation_when_snapshot_permissions_create_volume_group_all if {
    count(violation) == 1 with input as {
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ]
        },
        "volumes": [
            {
                "VolumeId": "vol-001",
                "Attachments": [
                    {"InstanceId": "i-1234567890abcdef0"}
                ]
            }
        ],
        "snapshot_inventory": [
            {
                "snapshot_id": "snap-001",
                "volume_id": "vol-001",
                "state": "completed",
                "public_share_enabled": false
            }
        ],
        "snapshot_permissions": [
            {
                "snapshot_id": "snap-001",
                "public_share_enabled": false,
                "CreateVolumePermissions": [
                    {"Group": "all"}
                ]
            }
        ]
    }
}
