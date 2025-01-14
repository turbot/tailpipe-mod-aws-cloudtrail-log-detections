## Description

This detection identifies Amazon CloudWatch log groups that are created without encryption enabled. Encrypting CloudWatch logs ensures that sensitive data within logs is protected at rest, reducing the risk of unauthorized access to critical information.

## Risks

Creating log groups without encryption can expose sensitive data to unauthorized access, particularly if the logs contain information such as application secrets, personally identifiable information (PII), or other confidential data. Without encryption, data stored in CloudWatch logs is more vulnerable to compromise in the event of a security breach.

Additionally, lack of encryption for log groups may lead to non-compliance with industry standards and regulatory requirements, such as PCI DSS, HIPAA, or GDPR. Enforcing encryption ensures that logs are stored securely and aligns with security best practices, safeguarding critical data and maintaining compliance.

## References

- [Encrypt log data in CloudWatch Logs using AWS Key Management Service](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html)
- [CloudWatch Logs Encryption Mode](https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/Glue/cloud-watch-logs-encryption-enabled.html)
- [AWS CLI Command: create-log-group](https://docs.aws.amazon.com/cli/latest/reference/logs/create-log-group.html)
