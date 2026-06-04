package compliance_framework.deny_unencrypted_root_volume

risk_templates := [{
  "name": "EC2 root volume encryption is not compliant",
  "title": "EC2 root volume encryption gap",
  "statement": "The EC2 instance root volume is missing from collected inventory or is not encrypted, increasing the risk that workload data on the primary boot volume can be exposed if the storage layer is accessed outside expected controls.",
  "likelihood_hint": "medium",
  "impact_hint": "high",
  "violation_ids": ["ec2_root_volume_encryption_not_compliant"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-311",
      "title": "Missing Encryption of Sensitive Data",
      "url": "https://cwe.mitre.org/data/definitions/311.html"
    }
  ],
  "remediation": {
    "title": "Ensure the EC2 root volume is present and encrypted",
    "description": "Confirm the root EBS volume can be resolved in inventory and that encryption is enabled for the boot volume used by the instance.",
    "tasks": [
      {"title": "Verify the root device mapping resolves to a collected EBS volume"},
      {"title": "Enable encryption for the root volume through an approved rebuild or replacement path"},
      {"title": "Update the launch template or AMI baseline so future instances inherit encrypted root storage"}
    ]
  }
}]

violation[{"id": "ec2_root_volume_encryption_not_compliant"}] if {
  some bdm in input.instance.BlockDeviceMappings
  bdm.DeviceName == input.instance.RootDeviceName
  not volume_in_inventory(bdm.Ebs.VolumeId)
}

violation[{"id": "ec2_root_volume_encryption_not_compliant"}] if {
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
