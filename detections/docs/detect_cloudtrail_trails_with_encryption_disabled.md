## Description

This detection identifies AWS CloudTrail trails that have encryption disabled. CloudTrail provides a record of actions taken in an AWS account, and enabling encryption ensures that these logs are securely stored and protected from unauthorized access. Disabling encryption increases the risk of log data exposure.

## Risks

CloudTrail logs often contain sensitive information about AWS account activity, such as API calls and resource changes. If encryption is disabled, the log data is stored in plaintext, making it vulnerable to unauthorized access. This could result in sensitive operational data being exposed or tampered with, compromising both security and compliance.

In addition, encryption is a key requirement for many regulatory frameworks and best practices. Disabling encryption for CloudTrail logs can lead to non-compliance with standards such as PCI DSS, HIPAA, or ISO 27001. Organizations may face increased risks of data breaches and operational disruptions without proper log encryption.

## References

- [AWS Documentation: Encrypting CloudTrail Logs with AWS KMS](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-kms.html)
- [AWS Documentation: Amazon S3 Server-Side Encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html)
- [AWS CLI Command: update-trail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html)
