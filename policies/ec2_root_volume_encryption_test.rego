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