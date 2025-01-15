## Overview

Detect Amazon CloudWatch Logs subscription filters configured to deliver log data to destinations in other AWS accounts via cross-account IAM roles. Improper configurations or excessive permissions can expose sensitive log data to unauthorized entities, increasing the risk of data breaches or compliance violations. Monitoring these configurations ensures secure and authorized cross-account log sharing.

**References**:
- [Log group-level subscription filters](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html)
- [Cross-account log data sharing with subscriptions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CrossAccountSubscriptions.html)
- [AWS CLI Command: put-subscription-filter](https://docs.aws.amazon.com/cli/latest/reference/logs/put-subscription-filter.html)
