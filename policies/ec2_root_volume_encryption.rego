package compliance_framework.deny_unencrypted_root_volume

violation[{}] if {
  some bdm in input.instance.BlockDeviceMappings
  bdm.DeviceName == input.instance.RootDeviceName
  not volume_in_inventory(bdm.Ebs.VolumeId)
}

violation[{}] if {
  some bdm in input.instance.BlockDeviceMappings
  bdm.DeviceName == input.instance.RootDeviceName
  some volume in input.volumes
  volume.VolumeId == bdm.Ebs.VolumeId
  not volume.Encrypted
}

volume_in_inventory(volume_id) if {
  volume_id != ""
  some volume in input.volumes
  volume.VolumeId == volume_id
}

title := "EC2 Instance encrypts it's root volume"
description := "EC2 Instances should encrypt their root EBS volume to ensure cryptographicly secure cloud operations"
