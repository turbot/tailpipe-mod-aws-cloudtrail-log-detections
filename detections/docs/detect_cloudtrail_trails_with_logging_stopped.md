## Description

This detection identifies AWS CloudTrail trails where logging has been stopped. CloudTrail logging is critical for capturing API activity and changes across AWS accounts. Disabling or stopping logging reduces visibility into account activity, making it difficult to monitor security events, troubleshoot issues, or maintain compliance.

## Risks

When logging is stopped for a CloudTrail trail, API activity and resource changes are no longer captured. This creates a gap in security monitoring and audit trails, increasing the risk of undetected malicious activity, such as unauthorized access, privilege escalation, or data exfiltration. Without these logs, incident response and forensic investigations become significantly more challenging.

Stopping logging may also indicate intentional or accidental mismanagement. An attacker with access to the account could stop logging to hide their activities. Continuous monitoring of CloudTrail logging status ensures timely detection and remediation of such actions, maintaining the integrity of security and compliance efforts.

## References

- [AWS Documentation: Managing CloudTrail Logging](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-enable.html)
- [AWS CLI Command: stop-logging](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/stop-logging.html)
- [AWS CLI Command: start-logging](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/start-logging.html)
