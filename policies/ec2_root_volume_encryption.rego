package compliance_framework.template.aws._deny_unencrypted_root_volume

controls := [
    # SAMA Cyber Security Framework v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-framework-2
    # Class: SAMA_CSF_1.0
    #
    # 3.3: Cyber Security Operations and Technology
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.8", # Infrastructure Security
        "statement-ids": [
            "4",
            "5",
            "6.a",
            "6.c",
            "6.d",
        ],
    },
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.9", # Cryptography
        "statement-ids": [
            "2",
            "3",
            "4.a",
            "4.b",
            "4.c",
        ],
    },
    # SAMA Cyber Resilience Fundamental Requirements v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-operations-and-technology
    # Class: SAMA_CRFR_1.0
    #
    # 3.2: Cyber Security Operations and Technology
    {
        "class": "SAMA_CRFR_1.0",
        "control-id": "3.2.4",
    },
    {
        "class": "SAMA_CRFR_1.0",
        "control-id": "3.2.8",
    },
]

violation[{
    "title": "EC2 instance is launched with the default security group",
    "description": sprintf("Instance '%v' is using the default security group", [input.InstanceID]),
    "remarks": "Ensure EC2 instances are not launched with the default security group. Define custom security groups with appropriate rules."
}] if {
    input.SecurityGroups[_].GroupName == "default"
}

violation[{
  "title": "Root volume is not encrypted",
}] if {
  some bdm in input.BlockDeviceMappings
  bdm.DeviceName == input.RootDeviceName
  not bdm.Ebs.Encrypted
}
