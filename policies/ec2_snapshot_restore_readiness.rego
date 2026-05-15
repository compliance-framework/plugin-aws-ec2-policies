package compliance_framework.snapshot_restore_readiness

violation[{}] if {
    count(attached_volume_ids) > 0
    not workload_has_usable_snapshots
}

violation[{}] if {
    count(attached_volume_ids) > 0
    recovery_objective_requires_fast_restore
    not workload_has_required_fast_restore
}

workload_has_usable_snapshots if {
    count(attached_volume_ids) > 0
    attached_volume_ids == snapshot_covered_volume_ids
}

attached_volume_ids[volume_id] if {
    instance := object.get(input, "instance", {})
    some bdm in object.get(instance, "BlockDeviceMappings", [])
    ebs := object.get(bdm, "Ebs", {})
    volume_id := object.get(ebs, "VolumeId", "")
    volume_id != ""
}

snapshot_covered_volume_ids[volume_id] if {
    attached_volume_ids[volume_id]
    some snapshot in object.get(input, "snapshots", [])
    snapshot_covers_volume(snapshot, volume_id)
}

snapshot_covers_volume(snapshot, volume_id) if {
    object.get(snapshot, "VolumeId", "") == volume_id
    lower(object.get(snapshot, "State", "")) == "completed"
    snapshot_is_owned(snapshot)
}

snapshot_is_owned(snapshot) if {
    account_id := object.get(input, "account_id", "")
    account_id == ""
}

snapshot_is_owned(snapshot) if {
    account_id := object.get(input, "account_id", "")
    account_id != ""
    object.get(snapshot, "OwnerId", "") == account_id
}

recovery_objective_requires_fast_restore if {
    recovery_objective := object.get(input, "recovery_objective", {})
    object.get(recovery_objective, "requires_fast_snapshot_restore", false)
}

workload_has_required_fast_restore if {
    attached_volume_ids == fast_restore_covered_volume_ids
}

fast_restore_covered_volume_ids[volume_id] if {
    attached_volume_ids[volume_id]
    some snapshot in object.get(input, "snapshots", [])
    snapshot_covers_volume(snapshot, volume_id)
    snapshot_id := object.get(snapshot, "SnapshotId", "")
    snapshot_id != ""
    fast_restore_enabled_for_snapshot(snapshot_id)
}

fast_restore_enabled_for_snapshot(snapshot_id) if {
    required_zone := required_fast_restore_zone
    some fast_restore in object.get(input, "fast_snapshot_restores", [])
    object.get(fast_restore, "SnapshotId", "") == snapshot_id
    lower(object.get(fast_restore, "AvailabilityZone", "")) == lower(required_zone)
    lower(object.get(fast_restore, "State", object.get(fast_restore, "fast_restore_state", ""))) == "enabled"
}

required_fast_restore_zone := zone if {
    recovery_objective := object.get(input, "recovery_objective", {})
    zone := object.get(recovery_objective, "availability_zone", "")
    zone != ""
}

required_fast_restore_zone := zone if {
    instance := object.get(input, "instance", {})
    placement := object.get(instance, "Placement", {})
    zone := object.get(placement, "AvailabilityZone", "")
    zone != ""
}

title := "EC2 / EBS workloads have recoverable backup artifacts"
description := "Each in-scope EBS-backed workload must have a usable completed owned snapshot, and where the documented restore objective requires it, Fast Snapshot Restore must be enabled in the required availability zone."
remarks := "Evaluates usable completed snapshot coverage and conditional Fast Snapshot Restore posture for attached EBS volumes."
