# Overview

AWS CloudTrail is a critical service that provides event history for account activity across your AWS environment. It enables visibility into actions taken by users, roles, or AWS services. Stopping or modifying CloudTrail logging disrupts this visibility, potentially allowing malicious actions to go undetected.

## Why is this Detection Necessary?

CloudTrail logs are fundamental to maintaining the security and compliance of AWS environments. Monitoring changes to trails helps organizations:
1. **Identifies Critical Changes**: Tracks actions such as stopping logging, deleting a trail, or updating a trail's configuration—activities that can have significant security implications.
2. **Prevents Misuse**: These actions could be malicious, such as an attacker attempting to disable logging to cover their tracks.
3. **Supports Compliance**: Many compliance frameworks (e.g., PCI DSS, GDPR, HIPAA) require continuous audit logging. Disabling CloudTrail could lead to compliance violations.
4. **Enhances Threat Hunting**: Highlights potential defense evasion tactics as part of broader malicious campaigns, aligning with MITRE ATT&CK techniques.

## References

- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html