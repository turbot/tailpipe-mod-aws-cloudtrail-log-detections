## Description

This detection identifies Amazon CloudWatch alarms that invoke actions in other AWS accounts via cross-account IAM roles. While cross-account actions can enable centralized management and collaboration, improper configurations or excessive permissions can expose sensitive operations to unauthorized entities.

## Risks

Configuring CloudWatch alarms to invoke cross-account actions without appropriate safeguards can lead to unauthorized or unintended operations in other accounts. Overly permissive IAM roles or insufficient access controls may allow malicious actors to abuse alarm actions to disrupt services, compromise resources, or escalate privileges in other accounts.

In addition, inadequate monitoring of cross-account alarm actions can make it challenging to audit and ensure compliance with organizational security policies. Ensuring that cross-account actions are properly authorized and configured is critical to maintaining the security and integrity of AWS resources across accounts.

## References

- [Amazon CloudWatch cross account alarms](https://aws.amazon.com/about-aws/whats-new/2021/08/announcing-amazon-cloudwatch-cross-account-alarms)
- [AWS CLI Command: put-metric-alarm](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/put-metric-alarm.html)
