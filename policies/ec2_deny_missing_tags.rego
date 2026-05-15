package compliance_framework.deny_missing_tags

violation[{}] if {
    missing_tags := {tag | tag := data.required_tags[_]; not tag_exists(input.instance.Tags, tag)}
    count(missing_tags) > 0
}

tag_exists(tags, tag_name) if {
    some tag in tags
     lower(tag.Key) == lower(tag_name)
}

title := "EC2 Instance sets correct tags"
description := "EC2 Instance tag set contains all the required tags as set out in policy"
remarks := "Policy ensures the required tags are set on EC2 instances (Environment, Owner, compliance, confidentiality, backup, role)"
