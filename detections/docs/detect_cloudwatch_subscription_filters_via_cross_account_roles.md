## Description

This detection identifies Amazon CloudWatch Logs subscription filters that are configured to deliver log data to destinations in other AWS accounts via cross-account IAM roles. While cross-account subscriptions can facilitate centralized log processing and monitoring, improper configurations or excessive permissions can expose sensitive log data to unauthorized entities.

## Risks

Configuring CloudWatch Logs subscription filters to send data across accounts without proper safeguards can lead to unauthorized access to sensitive information. Overly permissive IAM roles or misconfigured policies may allow external accounts to receive or manipulate log data, potentially resulting in data breaches or compliance violations.

Additionally, inadequate monitoring of cross-account log subscriptions can make it challenging to audit data flows and ensure adherence to security policies. Ensuring that cross-account subscriptions are properly authorized, configured with the principle of least privilege, and regularly monitored is essential to maintaining the security and integrity of log data.

## References

- [Log group-level subscription filters](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html)
- [Cross-account log data sharing with subscriptions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CrossAccountSubscriptions.html)
- [AWS CLI Command: put-subscription-filter](https://docs.aws.amazon.com/cli/latest/reference/logs/put-subscription-filter.html)
