package compliance_framework.deny_default_sg

risk_templates := [{
    "name": "EC2 default security group usage is not compliant",
    "title": "EC2 default security group reliance",
    "statement": "The EC2 instance is attached to the default security group, which increases the risk of unmanaged or overly broad network rules being inherited without explicit workload review.",
    "likelihood_hint": "medium",
    "impact_hint": "high",
    "violation_ids": ["ec2_default_security_group_in_use"],
    "threat_refs": [
        {
            "system": "https://cwe.mitre.org",
            "external_id": "CWE-284",
            "title": "Improper Access Control",
            "url": "https://cwe.mitre.org/data/definitions/284.html"
        }
    ],
    "remediation": {
        "title": "Attach an explicit workload security group",
        "description": "Replace the default security group with explicitly managed security groups that reflect the intended ingress and egress posture of the workload.",
        "tasks": [
            {"title": "Create or select a dedicated security group for the workload"},
            {"title": "Attach the explicit security group to the instance or launch template"},
            {"title": "Remove the default security group from the instance association"}
        ]
    }
}]

violation[{"id": "ec2_default_security_group_in_use"}] if {
    input.instance.SecurityGroups[_].GroupName == "default"
}

title := "EC2 Instance has explicit security group"
description := "EC2 Instance should be launched using an explicit security group, and avoid using the default security group."
