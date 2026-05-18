package compliance_framework.deny_unencrypted_root_volume

test_violation_unencrypted_root_volume if {
  violation[_] with input as {
    "instance": {
      "RootDeviceName": "/dev/xvda",
      "BlockDeviceMappings": [
        {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-123"}}
      ]
    },
    "volumes": [
      {"VolumeId": "vol-123", "Encrypted": false}
    ]
  }
}

test_no_violation_encrypted_root_volume if {
  count(violation) == 0 with input as {
    "instance": {
      "RootDeviceName": "/dev/xvda",
      "BlockDeviceMappings": [
        {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-123"}}
      ]
    },
    "volumes": [
      {"VolumeId": "vol-123", "Encrypted": true}
    ]
  }
}

test_violation_root_volume_missing_from_inventory if {
  count(violation) == 1 with input as {
    "instance": {
      "RootDeviceName": "/dev/xvda",
      "BlockDeviceMappings": [
        {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-123"}}
      ]
    },
    "volumes": []
  }
}