package compliance_framework.backup_artifact_approved_kms_encryption

violation[{}] if {
    attached_volume_ids[volume_id]
    not volume_is_encrypted(volume_id)
}

violation[{}] if {
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
