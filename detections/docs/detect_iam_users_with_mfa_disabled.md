## Description

This detection identifies IAM users with Multi-Factor Authentication (MFA) disabled. MFA adds an extra layer of security by requiring users to provide a second factor in addition to their password when signing in. Monitoring for users without MFA ensures that all accounts adhere to security best practices and reduces the risk of unauthorized access.

## Risks

IAM users with MFA disabled are at a higher risk of unauthorized access if their credentials are compromised. Without MFA, attackers who obtain a user's password can directly access the AWS Management Console or AWS APIs, potentially leading to data breaches, privilege escalation, or disruption of critical services.

The lack of MFA also increases the risk of non-compliance with industry standards or regulatory frameworks, which often require strong authentication controls. Monitoring for IAM users with MFA disabled ensures that all accounts are appropriately secured and helps enforce the principle of least privilege.

## References

- [AWS Documentation: Enabling MFA for IAM Users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html)
- [AWS CLI Command: enable-mfa-device](https://docs.aws.amazon.com/cli/latest/reference/iam/enable-mfa-device.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
