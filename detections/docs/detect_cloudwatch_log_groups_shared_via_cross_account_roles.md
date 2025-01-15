## Overview

Detect Amazon CloudWatch log groups shared with other AWS accounts via cross-account IAM roles. Improperly configured cross-account access can expose sensitive log data to unauthorized entities, increasing the risk of data breaches or misuse. Monitoring and enforcing granular permissions ensure the security and integrity of shared log data.

**References**:
- [Cross-Account Access in CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/permissions-reference-cwl.html#cross-account-logs)
- [AWS CLI Command: put-resource-policy](https://docs.aws.amazon.com/cli/latest/reference/logs/put-resource-policy.html)
