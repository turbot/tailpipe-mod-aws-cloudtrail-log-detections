## Description

This detection identifies instances where Amazon GuardDuty detectors are deleted. A GuardDuty detector is a key component of Amazon GuardDuty, enabling continuous monitoring of AWS accounts for malicious or unauthorized behavior. Deleting a detector disables threat detection and can leave an account vulnerable to security incidents.

## Risks

Deleting a GuardDuty detector effectively disables the service, stopping all threat detection and alerting capabilities for the affected AWS account. This leaves the account exposed to potential security threats, such as compromised credentials, unauthorized activity, or malicious behavior, without the ability to detect or respond.

Unauthorized or accidental deletion of a GuardDuty detector may indicate malicious activity, where an attacker aims to suppress security monitoring, or mismanagement that compromises the overall security posture. Regular monitoring of detector status ensures that GuardDuty remains active and provides continuous protection for AWS resources.

## References

- [Amazon GuardDuty Detectors](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_detectors.html)
- [AWS CLI Command: delete-detector](https://docs.aws.amazon.com/cli/latest/reference/guardduty/delete-detector.html)
