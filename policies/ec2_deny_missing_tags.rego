package compliance_framework.template.aws._deny_missing_tags

controls := [
    # SAMA Cyber Security Framework v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-framework-2
    # Class: SAMA_CSF_1.0
    #
    # 3.3: Cyber Security Operations and Technology
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.3", # Asset Management
        "statement-ids": [
            "3.b",
            "3.d",
            "3.e",
        ],
    },
    # SAMA Information Technology Governance Framework v1.0
    # https://rulebook.sama.gov.sa/en/information-technology-governance-framework
    # Class: SAMA_ITGF_1.0
    #
    # 3.3: Operations Management https://rulebook.sama.gov.sa/en/33-operations-management
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.3.1", # Manage Assets
        "statement-ids": [
            "2",
            "3.b",
            "4.a",
            "4.b",
            "4.e",
            "4.f",
            "4.g",
            "4.q",
            "5",
            "6.a",
            "7.a",
        ],
    },
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.3.4", # IT Availability and Capacity Management
        "statement-ids": [
            "2",
            "4.a",
            "4.d",
        ],
    },
    # SAMA Cyber Resilience Fundamental Requirements v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-operations-and-technology
    # Class: SAMA_CRFR_1.0
    #
    # 3.2: Cyber Security Operations and Technology
    {
        "class": "SAMA_CRFR_1.0",
        "control-id": "3.2.12",
    },
]

required_tags := ["Environment","Security","Compliance","Application","Cost Center","Project","Owner","Name"]

violation[{
    "title": "Check to ensure correct tags are set on EC2 Instances",
    "description": sprintf("Instance '%v' is missing required tags: %v", [input.InstanceID, missing_tags]),
    "remarks": "Ensure the following tags are set on the EC2 instance: Environment, Owner, compliance, confidentiality, backup, role."
}] if {
    missing_tags := {tag | tag := required_tags[_]; not tag_exists(input.Tags, tag)}
    count(missing_tags) > 0
}

tag_exists(tags, tag_name) if {
    some tag in tags
     lower(tag.Key) == lower(tag_name)
}
