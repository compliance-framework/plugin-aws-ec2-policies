package compliance_framework.snapshot_or_dlm_backup_coverage

violation[{}] if {
    count(attached_volume_ids) > 0
    not workload_has_backup_coverage
}

workload_has_backup_coverage if {
    workload_has_completed_snapshots
}

workload_has_backup_coverage if {
    workload_has_dlm_coverage
}

workload_has_completed_snapshots if {
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
    account_id != ""
    object.get(snapshot, "OwnerId", "") == account_id
}

workload_has_dlm_coverage if {
    some policy in object.get(input, "dlm_policies", [])
    dlm_policy_covers_workload(policy)
}

dlm_policy_covers_workload(policy) if {
    dlm_policy_is_enabled(policy)
    dlm_policy_has_retention(policy)
    policy_target_tags_match_instance(policy)
}

dlm_policy_is_enabled(policy) if {
    lower(object.get(policy, "State", object.get(policy, "policy_state", ""))) == "enabled"
}

dlm_policy_has_retention(policy) if {
    some schedule in object.get(policy, "Schedules", [])
    schedule_has_retention(schedule)
}

dlm_policy_has_retention(policy) if {
    details := object.get(policy, "PolicyDetails", {})
    some schedule in object.get(details, "Schedules", [])
    schedule_has_retention(schedule)
}

schedule_has_retention(schedule) if {
    retain_rule := object.get(schedule, "RetainRule", {})
    count_value := object.get(retain_rule, "Count", 0)
    is_number(count_value)
    count_value > 0
}

schedule_has_retention(schedule) if {
    retain_rule := object.get(schedule, "RetainRule", {})
    interval_value := object.get(retain_rule, "Interval", 0)
    is_number(interval_value)
    interval_value > 0
}

schedule_has_retention(schedule) if {
    retention_interval := object.get(schedule, "retention_interval", 0)
    is_number(retention_interval)
    retention_interval > 0
}

policy_target_tags_match_instance(policy) if {
    target_tags := {tag | some tag in object.get(policy, "TargetTags", [])}
    count(target_tags) > 0
    target_tags == {tag | some tag in object.get(policy, "TargetTags", []); instance_matches_target_tag(tag)}
}

policy_target_tags_match_instance(policy) if {
    details := object.get(policy, "PolicyDetails", {})
    target_tags := {tag | some tag in object.get(details, "TargetTags", [])}
    count(target_tags) > 0
    target_tags == {tag | some tag in object.get(details, "TargetTags", []); instance_matches_target_tag(tag)}
}

instance_matches_target_tag(tag) if {
    is_object(tag)
    key := object.get(tag, "Key", "")
    value := object.get(tag, "Value", "")
    key != ""
    value != ""
    instance := object.get(input, "instance", {})
    some instance_tag in object.get(instance, "Tags", [])
    lower(object.get(instance_tag, "Key", "")) == lower(key)
    lower(object.get(instance_tag, "Value", "")) == lower(value)
}

instance_matches_target_tag(tag) if {
    is_string(tag)
    contains(tag, "=")
    matches := regex.find_all_string_submatch_n("([^=]+)=(.*)", tag, -1)
    count(matches) > 0
    key := matches[0][1]
    value := matches[0][2]
    instance := object.get(input, "instance", {})
    some instance_tag in object.get(instance, "Tags", [])
    lower(object.get(instance_tag, "Key", "")) == lower(key)
    lower(object.get(instance_tag, "Value", "")) == lower(value)
}

title := "EC2 / EBS workloads have backup coverage"
description := "Each in-scope EBS-backed workload must have a completed owned snapshot for its attached volumes or be covered by an active DLM lifecycle policy with retention."
remarks := "Evaluates attached EBS volumes for completed owned snapshot coverage or matching DLM lifecycle coverage with retention."
