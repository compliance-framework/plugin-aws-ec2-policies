package compliance_framework.instance_metadata_v2_required

violation[{}] if {
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
