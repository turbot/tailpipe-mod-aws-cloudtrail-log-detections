## Description

This detection identifies AWS CloudTrail trails where the associated AWS Key Management Service (KMS) key has been updated. CloudTrail logs can be encrypted using a KMS key to ensure secure storage and prevent unauthorized access. Changes to the KMS key associated with a trail may impact log encryption and decryption operations.

## Risks

Updating the KMS key associated with a CloudTrail trail can introduce potential risks if not properly managed. If the new key lacks the appropriate permissions or is not properly configured, it could prevent CloudTrail from encrypting or decrypting log files, resulting in data loss or interruption in logging functionality.

Additionally, unauthorized or unapproved updates to the KMS key may indicate malicious activity or mismanagement. An attacker with access to the account could change the key to disrupt log encryption or hide their activities. Regularly monitoring for KMS key updates ensures that such changes are intentional, authorized, and aligned with security and compliance requirements.

## References

- [AWS Documentation: Encrypting CloudTrail Logs with AWS KMS](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html)
- [AWS CLI Command: update-trail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html)
