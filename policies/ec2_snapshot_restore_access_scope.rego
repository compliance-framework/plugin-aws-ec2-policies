package compliance_framework.snapshot_restore_access_scope

violation[{}] if {
    attached_volume_ids[volume_id]
    not volume_is_attached_to_instance(volume_id)
}

violation[{}] if {
    some snapshot in object.get(input, "snapshot_inventory", [])
    snapshot_is_in_scope(snapshot)
    snapshot_is_public(snapshot)
}

attached_volume_ids[volume_id] if {
    instance := object.get(input, "instance", {})
    some bdm in object.get(instance, "BlockDeviceMappings", [])
    ebs := object.get(bdm, "Ebs", {})
    volume_id := object.get(ebs, "VolumeId", "")
    volume_id != ""
}

volume_is_attached_to_instance(volume_id) if {
    attached_volume_ids[volume_id]
    instance_id := object.get(object.get(input, "instance", {}), "InstanceId", "")
    instance_id != ""
    some volume in object.get(input, "volumes", [])
    object.get(volume, "VolumeId", "") == volume_id
    some attachment in object.get(volume, "Attachments", [])
    object.get(attachment, "InstanceId", "") == instance_id
}

snapshot_is_in_scope(snapshot) if {
    attached_volume_ids[volume_id]
    object.get(snapshot, "volume_id", "") == volume_id
    lower(object.get(snapshot, "state", "")) == "completed"
    object.get(snapshot, "snapshot_id", "") != ""
}

snapshot_is_public(snapshot) if {
    snapshot_id := object.get(snapshot, "snapshot_id", "")
    some permission in object.get(input, "snapshot_permissions", [])
    object.get(permission, "snapshot_id", "") == snapshot_id
    object.get(permission, "public_share_enabled", false)
}

snapshot_is_public(snapshot) if {
    snapshot_id := object.get(snapshot, "snapshot_id", "")
    some permission in object.get(input, "snapshot_permissions", [])
    object.get(permission, "snapshot_id", "") == snapshot_id
    some create_volume_permission in object.get(permission, "CreateVolumePermissions", [])
    lower(object.get(create_volume_permission, "Group", "")) == "all"
}

snapshot_is_public(snapshot) if {
    object.get(snapshot, "public_share_enabled", false)
}

title := "EC2 snapshots have constrained restore access"
description := "Attached EBS volumes must resolve to the evaluated instance, and in-scope completed snapshots must not be publicly restorable. Explicit account shares are treated as approved when present."
remarks := "Evaluates attached volume-to-instance lineage together with snapshot permission posture using snapshot inventory and derived public sharing flags."
