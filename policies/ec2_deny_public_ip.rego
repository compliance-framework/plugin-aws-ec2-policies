package compliance_framework.deny_deny_public_ip

violation[{}] if {
    input.PublicIP != ""
    input.PublicIP != null
}

title := "EC2 Instance does not expose a Public IP"
description := "EC2 Instance has no public IP assigned in AWS and only has private IPs"
