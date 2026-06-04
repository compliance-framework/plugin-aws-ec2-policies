package compliance_framework.backup_artifact_approved_kms_encryption

risk_templates := [{
    "name": "EC2 backup artifact encryption is not compliant",
    "title": "EC2 backup artifact encryption gap",
    "statement": "Attached EBS volumes or recoverable snapshots for the EC2 workload are not encrypted, increasing the risk that live data or backup artifacts can be read outside approved key protections.",
    "likelihood_hint": "medium",
    "impact_hint": "high",
    "violation_ids": ["ec2_backup_artifact_encryption_not_compliant"],
    "threat_refs": [
        {
            "system": "https://cwe.mitre.org",
            "external_id": "CWE-311",
            "title": "Missing Encryption of Sensitive Data",
            "url": "https://cwe.mitre.org/data/definitions/311.html"
        }
    ],
    "remediation": {
        "title": "Keep attached volumes and recoverable snapshots encrypted",
        "description": "Ensure attached EBS volumes and completed in-scope snapshots remain encrypted across the workload recovery path.",
        "tasks": [
            {"title": "Confirm every attached volume is encrypted"},
            {"title": "Ensure completed snapshots for in-scope volumes are encrypted"},
            {"title": "Update backup and image creation paths so new artifacts inherit encryption by default"}
        ]
    }
}]

violation[{"id": "ec2_backup_artifact_encryption_not_compliant"}] if {
    attached_volume_ids[volume_id]
    not volume_is_encrypted(volume_id)
}

violation[{"id": "ec2_backup_artifact_encryption_not_compliant"}] if {
    some snapshot in object.get(input, "snapshot_inventory", [])
    snapshot_is_in_scope(snapshot)
    not snapshot_is_encrypted(snapshot)
}

attached_volume_ids[volume_id] if {
    instance := object.get(input, "instance", {})
    some bdm in object.get(instance, "BlockDeviceMappings", [])
    ebs := object.get(bdm, "Ebs", {})
    volume_id := object.get(ebs, "VolumeId", "")
    volume_id != ""
}

volume_is_encrypted(volume_id) if {
    attached_volume_ids[volume_id]
    some volume in object.get(input, "volumes", [])
    object.get(volume, "VolumeId", "") == volume_id
    object.get(volume, "Encrypted", false)
}

snapshot_is_in_scope(snapshot) if {
    attached_volume_ids[volume_id]
    object.get(snapshot, "volume_id", "") == volume_id
    lower(object.get(snapshot, "state", "")) == "completed"
    object.get(snapshot, "snapshot_id", "") != ""
}

snapshot_is_encrypted(snapshot) if {
    object.get(snapshot, "encrypted", false)
}

title := "EC2 backup artifacts remain encrypted"
description := "Attached EBS volumes and completed in-scope snapshots must remain encrypted."
remarks := "Evaluates live attached volume encryption together with recoverable snapshot inventory encryption regardless of KMS key type."
