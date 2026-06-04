package compliance_framework.instance_metadata_v2_required

risk_templates := [{
    "name": "EC2 instance metadata protection is not compliant",
    "title": "EC2 instance metadata exposure risk",
    "statement": "The EC2 instance metadata service is enabled without requiring IMDSv2 session tokens, increasing the chance that metadata can be accessed through unintended request paths or SSRF-style abuse.",
    "likelihood_hint": "medium",
    "impact_hint": "high",
    "violation_ids": ["ec2_imdsv2_not_required"],
    "threat_refs": [
        {
            "system": "https://cwe.mitre.org",
            "external_id": "CWE-918",
            "title": "Server-Side Request Forgery (SSRF)",
            "url": "https://cwe.mitre.org/data/definitions/918.html"
        }
    ],
    "remediation": {
        "title": "Require IMDSv2 session tokens or disable instance metadata",
        "description": "Configure the instance metadata endpoint to require IMDSv2 session tokens whenever metadata access is enabled, or disable the endpoint if it is not needed.",
        "tasks": [
            {"title": "Set HttpTokens to required for the instance or launch template"},
            {"title": "Disable the metadata endpoint if the workload does not need it"},
            {"title": "Review application components for any reliance on legacy IMDSv1 access"}
        ]
    }
}]

violation[{"id": "ec2_imdsv2_not_required"}] if {
    metadata_endpoint_enabled
    not metadata_tokens_required
}

metadata_endpoint_enabled if {
    instance := object.get(input, "instance", {})
    metadata_options := object.get(instance, "MetadataOptions", {})
    lower(object.get(metadata_options, "HttpEndpoint", "enabled")) != "disabled"
}

metadata_tokens_required if {
    instance := object.get(input, "instance", {})
    metadata_options := object.get(instance, "MetadataOptions", {})
    lower(object.get(metadata_options, "HttpTokens", "")) == "required"
}

title := "EC2 instance metadata requires IMDSv2"
description := "The EC2 instance metadata endpoint must either be disabled or require session tokens via IMDSv2."
remarks := "Evaluates EC2 instance metadata options and requires HttpTokens to be set to required whenever the metadata endpoint is enabled."
