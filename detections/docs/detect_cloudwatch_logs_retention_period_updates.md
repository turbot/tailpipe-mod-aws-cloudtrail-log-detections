## Description

This detection identifies updates to the retention period of Amazon CloudWatch log groups. The retention period determines how long log data is stored before it is automatically deleted. Changes to retention settings may impact compliance, auditing, and the availability of critical log data.

## Risks

Modifying the retention period of CloudWatch log groups can lead to the premature deletion of logs, resulting in the loss of critical operational, security, or compliance data. Shortening the retention period may make it difficult to investigate past incidents, meet regulatory requirements, or perform historical analysis.

Unauthorized or accidental updates to log retention settings may also indicate mismanagement or malicious activity. An attacker could shorten the retention period to erase evidence of their actions. Monitoring changes to log retention settings ensures logs are retained for the required duration and safeguards operational and security visibility.

## References

- [Set Log Retention in CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html#SettingLogRetention)
- [Securing CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/security.html)
- [AWS CLI Command: put-retention-policy](https://docs.aws.amazon.com/cli/latest/reference/logs/put-retention-policy.html)
