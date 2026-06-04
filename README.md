# AWS EC2 policies

Standalone OPA/Rego policy bundle for EC2 evidence emitted by the `plugin-aws-ec2` collector.

## Input schema

Each policy evaluates one EC2 instance at a time using:

- `input.region`
- `input.instance`
- `input.security_groups`
- `input.volumes`
- `input.snapshots`
- `input.snapshot_inventory`
- `input.snapshot_permissions`
- `input.images`
- `input.fast_snapshot_restore`

Current EC2 input includes the current instance summary, attached security groups, attached EBS volumes, account-owned snapshots for attached volumes, derived snapshot inventory, snapshot restore permissions, related account-owned AMIs, and Fast Snapshot Restore state.


## Current coverage

This bundle currently checks EC2 compute, network, storage, and recovery posture such as:

- public IP exposure on the instance or network interfaces
- use of default security groups
- public all-traffic ingress through attached security groups
- required EC2 instance tags
- IMDSv2 enforcement when the instance metadata endpoint is enabled
- root EBS volume encryption
- attached volume and backup artifact encryption
- completed snapshot or DLM backup coverage for attached EBS volumes
- snapshot restore readiness, including conditional Fast Snapshot Restore posture
- constrained snapshot restore access and public snapshot sharing

## Policy data

Default baselines live in `policies/data.json` and can be overridden by agent-supplied policy data. Current settings cover required EC2 instance tags.

## Testing

Run local checks with:

```shell
opa check policies
opa test policies
```

Or use the Makefile wrappers:

```shell
make validate
make test
```

## Bundling

Build the distributable bundle with:

```shell
make build
```

This writes `dist/bundle.tar.gz`.
