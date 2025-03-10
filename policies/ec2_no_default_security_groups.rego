
package compliance_framework.template.aws._deny_default_sg

violation[{
    "title": "EC2 instance is launched with the default security group",
    "description": sprintf("Instance '%v' is using the default security group", [input.InstanceID]),
    "remarks": "Ensure EC2 instances are not launched with the default security group. Define custom security groups with appropriate rules."
}] if {
    input.SecurityGroups[_].GroupName == "default"
}