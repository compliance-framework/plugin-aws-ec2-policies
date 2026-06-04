package compliance_framework.deny_public_ip

risk_templates := [{
    "name": "EC2 public IP exposure is not compliant",
    "title": "EC2 public network exposure",
    "statement": "The EC2 instance exposes a public IP address, increasing its direct internet attack surface and the chance of unintended external reachability.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "violation_ids": ["ec2_public_ip_exposed"],
    "threat_refs": [
        {
            "system": "https://cwe.mitre.org",
            "external_id": "CWE-668",
            "title": "Exposure of Resource to Wrong Sphere",
            "url": "https://cwe.mitre.org/data/definitions/668.html"
        }
    ],
    "remediation": {
        "title": "Remove direct public IP exposure from the instance",
        "description": "Ensure the EC2 instance does not have a public IP address unless that internet exposure is explicitly required and approved.",
        "tasks": [
            {"title": "Remove the public IPv4 association from the instance or its network interface"},
            {"title": "Use private subnets and controlled egress paths such as NAT where appropriate"},
            {"title": "Review whether any workload requirement still depends on direct public addressing"}
        ]
    }
}]

violation[{"id": "ec2_public_ip_exposed"}] if {
    input.instance.PublicIpAddress != ""
    input.instance.PublicIpAddress != null
}

violation[{"id": "ec2_public_ip_exposed"}] if {
    some interface in object.get(input.instance, "NetworkInterfaces", [])
    association := object.get(interface, "Association", {})
    public_ip := object.get(association, "PublicIp", "")
    public_ip != ""
    public_ip != null
}

title := "EC2 Instance does not expose a Public IP"
description := "EC2 Instance has no public IP assigned in AWS and only has private IPs"
