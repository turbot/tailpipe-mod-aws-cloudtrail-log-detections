## Description

This detection identifies Amazon CloudWatch log groups that are shared with other AWS accounts via cross-account IAM roles. While cross-account access can facilitate collaboration and centralized logging, improper configuration or excessive permissions can expose sensitive log data to unauthorized entities.

## Risks

Sharing CloudWatch log groups across accounts without proper controls can lead to sensitive data being accessed or misused by unauthorized parties. Overly permissive IAM roles or sharing with untrusted accounts may expose operational, security, or compliance data, increasing the risk of data breaches or misuse.

Additionally, inadequate monitoring of cross-account access may make it difficult to track and audit who has accessed log data. Configuring granular permissions and monitoring cross-account access are essential for maintaining the security and integrity of log data while enabling legitimate collaboration.

## References

- [Cross-Account Access in CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/permissions-reference-cwl.html#cross-account-logs)
- [AWS CLI Command: put-resource-policy](https://docs.aws.amazon.com/cli/latest/reference/logs/put-resource-policy.html)
