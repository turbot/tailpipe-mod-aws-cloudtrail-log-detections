## Description

This detection identifies AWS CloudTrail trails where S3 logging has been disabled. CloudTrail logs are stored in Amazon S3 buckets, and disabling S3 logging can compromise the visibility of access and changes to log files. Ensuring S3 logging is enabled provides an additional layer of security and accountability for log data.

## Risks

Disabling S3 logging for CloudTrail trails can obscure access patterns to log files, making it harder to detect unauthorized access or tampering. Without logging enabled on the S3 bucket, it becomes challenging to track who accessed or modified the log files, potentially compromising the integrity and security of critical operational data.

Such configurations may indicate accidental mismanagement or malicious intent, where an attacker seeks to obscure their actions. Enabling and monitoring S3 logging is essential to maintain a robust security posture, ensure audit trails are intact, and meet compliance requirements for log management and monitoring.

## References

- [AWS Documentation: Configuring Amazon S3 Buckets for CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)
- [AWS CLI Command: put-event-selectors](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/put-event-selectors.html)
