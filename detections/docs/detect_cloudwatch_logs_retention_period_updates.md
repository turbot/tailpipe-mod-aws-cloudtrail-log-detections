## Overview

Detect updates to the retention period of Amazon CloudWatch log groups. Modifying retention settings can lead to the premature deletion of critical logs, impacting compliance, auditing, and historical analysis. Monitoring retention period changes ensures logs are stored for the required duration and maintains operational and security visibility.

**References**:
- [Set Log Retention in CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html#SettingLogRetention)
- [Securing CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/security.html)
- [AWS CLI Command: put-retention-policy](https://docs.aws.amazon.com/cli/latest/reference/logs/put
