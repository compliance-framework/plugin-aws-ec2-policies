package compliance_framework.public_all_traffic_ingress

risk_templates := [{
    "name": "EC2 attached security group ingress is not compliant",
    "title": "EC2 internet ingress exposure",
    "statement": "One or more security groups attached to the EC2 instance allow unrestricted inbound traffic from public IPv4 or IPv6 sources, increasing the likelihood of unauthorized network access.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "violation_ids": ["ec2_public_all_traffic_ingress_not_compliant"],
    "threat_refs": [
        {
            "system": "https://cwe.mitre.org",
            "external_id": "CWE-284",
            "title": "Improper Access Control",
            "url": "https://cwe.mitre.org/data/definitions/284.html"
        }
    ],
    "remediation": {
        "title": "Restrict public all-traffic ingress on attached security groups",
        "description": "Ensure security groups attached to the EC2 instance do not permit all inbound traffic from 0.0.0.0/0 or ::/0 unless that exposure is explicitly intended and approved.",
        "tasks": [
            {"title": "Remove any inbound rule that permits all protocols from public IPv4 or IPv6 ranges"},
            {"title": "Replace broad exposure with the minimum required ports, protocols, and source ranges"},
            {"title": "Confirm the plugin can resolve all attached security groups in the collected inventory"}
        ]
    }
}]

violation[{"id": "ec2_public_all_traffic_ingress_not_compliant"}] if {
    attached_security_group_ids[group_id]
    not security_group_in_inventory(group_id)
}

violation[{"id": "ec2_public_all_traffic_ingress_not_compliant"}] if {
    attached_security_group_ids[group_id]
    security_group_allows_public_all_traffic_ingress(group_id)
}

attached_security_group_ids[group_id] if {
    instance := object.get(input, "instance", {})
    some security_group in object.get(instance, "SecurityGroups", [])
    group_id := object.get(security_group, "GroupId", "")
    group_id != ""
}

security_group_in_inventory(group_id) if {
    group_id != ""
    some security_group in object.get(input, "security_groups", [])
    object.get(security_group, "GroupId", "") == group_id
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
