package compliance_framework.deny_deny_public_ip

violation[{}] if {
    input.instance.PublicIpAddress != ""
    input.instance.PublicIpAddress != null
}

violation[{}] if {
    some interface in object.get(input.instance, "NetworkInterfaces", [])
    association := object.get(interface, "Association", {})
    public_ip := object.get(association, "PublicIp", "")
    public_ip != ""
    public_ip != null
}

violation[{}] if {
    some interface in object.get(input.instance, "NetworkInterfaces", [])
    some ipv6_address in object.get(interface, "Ipv6Addresses", [])
    ipv6_address.Ipv6Address != ""
    ipv6_address.Ipv6Address != null
}

title := "EC2 Instance does not expose a Public IP"
description := "EC2 Instance has no public IP assigned in AWS and only has private IPs"
