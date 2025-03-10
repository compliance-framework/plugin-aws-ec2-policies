package compliance_framework.template.aws._deny_public_ip

violation[{
    "title": "Check to ensure EC2 instance does not have a public IP",
    "description": sprintf("Instance '%v' has a public IP address, which is not allowed.", [input.InstanceID]),
    "remarks": "Ensure the EC2 instance does not have a public IP address."
}] if {
    input.PublicIP != ""
    input.PublicIP != null
}