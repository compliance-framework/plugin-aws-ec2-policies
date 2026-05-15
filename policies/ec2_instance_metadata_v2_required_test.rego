package compliance_framework.instance_metadata_v2_required

test_violation_when_metadata_endpoint_enabled_and_tokens_are_optional if {
    count(violation) == 1 with input as {
        "instance": {
            "MetadataOptions": {
                "HttpEndpoint": "enabled",
                "HttpTokens": "optional"
            }
        }
    }
}

test_no_violation_when_metadata_endpoint_enabled_and_tokens_are_required if {
    count(violation) == 0 with input as {
        "instance": {
            "MetadataOptions": {
                "HttpEndpoint": "enabled",
                "HttpTokens": "required"
            }
        }
    }
}

test_no_violation_when_metadata_endpoint_is_disabled if {
    count(violation) == 0 with input as {
        "instance": {
            "MetadataOptions": {
                "HttpEndpoint": "disabled",
                "HttpTokens": "optional"
            }
        }
    }
}
