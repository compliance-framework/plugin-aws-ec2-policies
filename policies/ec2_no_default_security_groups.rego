package compliance_framework.deny_default_sg

violation[{}] if {
    input.SecurityGroups[_].GroupName == "default"
}

title := "EC2 Instance has explicit security group"
description := "EC2 Instance should be launched using an explicit security group, and avoid using the default security group."
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
            "5",
            "6.a",
            "6.d",
            "6.e",
            "6.h",
        ],
    },
    # SAMA Information Technology Governance Framework v1.0
    # https://rulebook.sama.gov.sa/en/information-technology-governance-framework
    # Class: SAMA_ITGF_1.0
    #
    # 3.3: Operations Management https://rulebook.sama.gov.sa/en/33-operations-management
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.3.6", # Network Architecture and Monitoring
        "statement-ids": [
            "1.a",
            "1.b",
            "2.b",
            "2.d",
            "2.o",
        ],
    },
    # SAMA Cyber Resilience Fundamental Requirements v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-operations-and-technology
    # Class: SAMA_CRFR_1.0
    #
    # 3.2: Cyber Security Operations and Technology
    {
        "class": "SAMA_CRFR_1.0",
        "control-id": "3.2.1",
    },
    {
        "class": "SAMA_CRFR_1.0",
        "control-id": "3.2.3",
    },
]

