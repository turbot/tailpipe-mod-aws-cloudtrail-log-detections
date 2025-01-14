## Description

This detection identifies updates to subscription filters for Amazon CloudWatch log groups. Subscription filters specify how log events are forwarded to other AWS services, such as Amazon Kinesis, AWS Lambda, or Amazon S3. Unauthorized or unintended changes to subscription filters can disrupt log delivery or redirect sensitive data to unapproved destinations.

## Risks

Updating subscription filters without proper oversight can lead to significant risks. For example, removing or misconfiguring a filter may interrupt the flow of logs to downstream systems, hindering monitoring, analysis, and compliance efforts. Conversely, adding overly broad filters may expose sensitive log data to unauthorized destinations.

Such changes may also indicate malicious activity, where an attacker could redirect logs to avoid detection or delete subscription filters to disrupt logging altogether. Monitoring updates to subscription filters ensures the integrity of log delivery and helps maintain a secure and compliant logging pipeline.

## References

- [Subscription Filters with CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html)
- [AWS CLI Command: put-subscription-filter](https://docs.aws.amazon.com/cli/latest/reference/logs/put-subscription-filter.html)
- [AWS CLI Command: delete-subscription-filter](https://docs.aws.amazon.com/cli/latest/reference/logs/delete-subscription-filter.html)
