package compliance_framework.deny_unencrypted_root_volume

violation[{}] if {
  some bdm in input.BlockDeviceMappings
  bdm.DeviceName == input.RootDeviceName
  not bdm.Ebs.Encrypted
}

title := "EC2 Instance encrypts it's root volume"
description := "EC2 Instances should encrypt their root EBS volume to ensure cryptographicly secure cloud operations"
