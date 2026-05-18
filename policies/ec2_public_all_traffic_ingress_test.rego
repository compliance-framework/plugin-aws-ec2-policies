package compliance_framework.public_all_traffic_ingress

test_violation_when_attached_sg_allows_public_all_traffic_ingress if {
    count(violation) == 1 with input as {
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "SecurityGroups": [
                {"GroupId": "sg-001", "GroupName": "open-sg"}
            ]
        },
        "security_groups": [
            {
                "GroupId": "sg-001",
                "GroupName": "open-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0"}
                        ],
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }
}

test_violation_when_attached_sg_allows_public_all_traffic_ingress_ipv6 if {
    count(violation) == 1 with input as {
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "SecurityGroups": [
                {"GroupId": "sg-001", "GroupName": "open-sg"}
            ]
        },
        "security_groups": [
            {
                "GroupId": "sg-001",
                "GroupName": "open-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "all",
                        "IpRanges": [],
                        "Ipv6Ranges": [
                            {"CidrIpv6": "::/0"}
                        ]
                    }
                ]
            }
        ]
    }
}

test_no_violation_when_attached_sg_does_not_allow_public_all_traffic_ingress if {
    count(violation) == 0 with input as {
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "SecurityGroups": [
                {"GroupId": "sg-001", "GroupName": "restricted-sg"}
            ]
        },
        "security_groups": [
            {
                "GroupId": "sg-001",
                "GroupName": "restricted-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {"CidrIp": "10.0.0.0/8"}
                        ],
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }
}

test_violation_when_attached_sg_missing_from_inventory if {
    count(violation) == 1 with input as {
        "instance": {
            "InstanceId": "i-1234567890abcdef0",
            "SecurityGroups": [
                {"GroupId": "sg-001", "GroupName": "missing-sg"}
            ]
        },
        "security_groups": []
    }
}
