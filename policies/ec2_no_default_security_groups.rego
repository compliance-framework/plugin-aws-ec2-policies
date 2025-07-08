package compliance_framework.deny_default_sg

violation[{}] if {
    input.SecurityGroups[_].GroupName == "default"
}

title := "EC2 Instance has explicit security group"
description := "EC2 Instance should be launched using an explicit security group, and avoid using the default security group."
