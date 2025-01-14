## Description

This detection identifies Amazon Elastic Block Store (EBS) snapshots that are created without encryption. Encrypting EBS snapshots ensures that data at rest is protected and reduces the risk of unauthorized access to sensitive information. Unencrypted snapshots can expose data to security vulnerabilities and compliance risks.

## Risks

Creating EBS snapshots without encryption can lead to the storage of sensitive data in plaintext, making it accessible to unauthorized users in the event of a security breach. This is particularly concerning in environments that handle sensitive workloads, such as financial data, personally identifiable information (PII), or intellectual property.

In addition, unencrypted EBS snapshots may lead to non-compliance with regulatory frameworks and industry standards, such as PCI DSS, GDPR, or HIPAA. Organizations may face legal and financial penalties if sensitive data is exposed due to insufficient encryption practices. Enforcing encryption for EBS snapshots is a critical step in maintaining a secure and compliant cloud environment.

## References

- [Encrypting EBS Snapshots](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
- [Amazon EBS Best Practices](https://docs.aws.amazon.com/prescriptive-guidance/latest/encryption-best-practices/ec2-ebs.html)
- [AWS CLI Command: disable-ebs-encryption-by-default](https://docs.aws.amazon.com/cli/latest/reference/ec2/disable-ebs-encryption-by-default.html)
