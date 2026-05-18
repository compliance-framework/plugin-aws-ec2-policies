package compliance_framework.backup_artifact_approved_kms_encryption

test_violation_when_attached_volume_is_not_encrypted if {
    count(violation) == 1 with input as {
        "instance": {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ]
        },
        "volumes": [
            {
                "VolumeId": "vol-001",
                "Encrypted": false,
                "KmsKeyId": "arn:aws:kms:eu-west-2:123456789012:alias/aws/ebs"
            }
        ],
        "snapshot_inventory": []
    }
}

test_violation_when_in_scope_snapshot_is_not_encrypted if {
    count(violation) == 1 with input as {
        "instance": {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ]
        },
        "volumes": [
            {
                "VolumeId": "vol-001",
                "Encrypted": true,
                "KmsKeyId": "arn:aws:kms:eu-west-2:123456789012:key/11111111-1111-1111-1111-111111111111"
            }
        ],
        "snapshot_inventory": [
            {
                "snapshot_id": "snap-001",
                "volume_id": "vol-001",
                "state": "completed",
                "encrypted": false,
                "kms_key_id": "arn:aws:kms:eu-west-2:123456789012:alias/aws/ebs"
            }
        ]
    }
}

test_no_violation_when_attached_volume_and_snapshot_are_encrypted if {
    count(violation) == 0 with input as {
        "instance": {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ]
        },
        "volumes": [
            {
                "VolumeId": "vol-001",
                "Encrypted": true,
                "KmsKeyId": "arn:aws:kms:eu-west-2:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            }
        ],
        "snapshot_inventory": [
            {
                "snapshot_id": "snap-001",
                "volume_id": "vol-001",
                "state": "completed",
                "encrypted": true,
                "kms_key_id": "arn:aws:kms:eu-west-2:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            }
        ]
    }
}

test_no_violation_when_attached_volume_and_snapshot_use_aws_managed_kms_if_encrypted if {
    count(violation) == 0 with input as {
        "instance": {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-001"}}
            ]
        },
        "volumes": [
            {
                "VolumeId": "vol-001",
                "Encrypted": true,
                "KmsKeyId": "arn:aws:kms:eu-west-2:123456789012:alias/aws/ebs"
            }
        ],
        "snapshot_inventory": [
            {
                "snapshot_id": "snap-001",
                "volume_id": "vol-001",
                "state": "completed",
                "encrypted": true,
                "kms_key_id": "arn:aws:kms:eu-west-2:123456789012:alias/aws/ebs"
            }
        ]
    }
}
