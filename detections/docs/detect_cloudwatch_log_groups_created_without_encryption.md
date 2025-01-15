## Overview

Detect Amazon CloudWatch log groups created without encryption enabled. Unencrypted logs are more vulnerable to unauthorized access, exposing sensitive information such as application secrets or personally identifiable information (PII). Enabling encryption ensures secure log storage and compliance with industry standards.

**References**:
- [Encrypt log data in CloudWatch Logs using AWS Key Management Service](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html)
- [CloudWatch Logs Encryption Mode](https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/Glue/cloud-watch-logs-encryption-enabled.html)
- [AWS CLI Command: create-log-group](https://docs.aws.amazon.com/cli/latest/reference/logs/create-log-group.html)
