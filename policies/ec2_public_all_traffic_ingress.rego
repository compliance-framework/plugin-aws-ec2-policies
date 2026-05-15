package compliance_framework.public_all_traffic_ingress

violation[{}] if {
    attached_security_group_ids[group_id]
    security_group_allows_public_all_traffic_ingress(group_id)
}

attached_security_group_ids[group_id] if {
    instance := object.get(input, "instance", {})
    some security_group in object.get(instance, "SecurityGroups", [])
    group_id := object.get(security_group, "GroupId", "")
    group_id != ""
}

security_group_allows_public_all_traffic_ingress(group_id) if {
    some security_group in object.get(input, "security_groups", [])
    object.get(security_group, "GroupId", "") == group_id
    some permission in object.get(security_group, "IpPermissions", [])
    ingress_permission_allows_all_traffic(permission)
    ingress_permission_is_public(permission)
}

ingress_permission_allows_all_traffic(permission) if {
    lower(object.get(permission, "IpProtocol", "")) == "-1"
}

ingress_permission_allows_all_traffic(permission) if {
    lower(object.get(permission, "IpProtocol", "")) == "all"
}

ingress_permission_is_public(permission) if {
    some ip_range in object.get(permission, "IpRanges", [])
    object.get(ip_range, "CidrIp", "") == "0.0.0.0/0"
}

ingress_permission_is_public(permission) if {
    some ipv6_range in object.get(permission, "Ipv6Ranges", [])
    object.get(ipv6_range, "CidrIpv6", "") == "::/0"
}

title := "EC2 attached security groups do not allow public all-traffic ingress"
description := "Security groups attached to the evaluated EC2 instance must not allow all inbound traffic from public IPv4 or IPv6 sources."
remarks := "Evaluates attached security group ingress rules and flags IpPermissions that allow all traffic from 0.0.0.0/0 or ::/0."
