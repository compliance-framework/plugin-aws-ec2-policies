package compliance_framework.template.aws._deny_unencrypted_root_volume

violation[{
  "title": "Root volume is not encrypted",
}] if {
  some bdm in input.BlockDeviceMappings
  bdm.DeviceName == input.RootDeviceName
  not bdm.Ebs.Encrypted
}
