## Description

This detection identifies instances where AWS Key Management Service (KMS) keys are deleted. KMS keys are essential for encrypting data at rest and in transit across various AWS services. Deleting a KMS key can render encrypted data inaccessible and disrupt critical operations that depend on the key.

## Risks

Deleting a KMS key can have severe consequences, as all data encrypted with that key becomes unrecoverable once the key is permanently deleted. This can result in data loss, application downtime, and disruption of workflows that rely on the key for encryption and decryption operations.

Unauthorized or accidental deletion of KMS keys may indicate malicious activity or mismanagement. An attacker might delete a key to disrupt services or render critical data inaccessible. Monitoring KMS key deletions is essential to maintain data availability, protect sensitive information, and ensure operational continuity.

## References

- [AWS Key Management Service (KMS) Keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)
- [AWS CLI Command: schedule-key-deletion](https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html)
- [AWS CLI Command: cancel-key-deletion](https://docs.aws.amazon.com/cli/latest/reference/kms/cancel-key-deletion.html)
