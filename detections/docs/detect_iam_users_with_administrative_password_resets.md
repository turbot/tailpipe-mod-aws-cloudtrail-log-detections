## Description

This detection identifies IAM users whose passwords have been reset by an administrator. Administrative password resets can occur for legitimate reasons, such as account recovery or security incidents, but they can also indicate unauthorized activity or privilege misuse. Monitoring such events ensures the security and integrity of IAM user accounts.

## Risks

Administrative password resets for IAM users pose potential security risks, as they may indicate unauthorized access or account manipulation. An attacker or malicious insider with administrative privileges could reset a user's password to gain access to their account, bypassing standard authentication mechanisms. This could result in unauthorized access to sensitive resources or data.

Frequent or unexplained password resets can also indicate potential misuse of administrative privileges or poor security practices. Monitoring password resets helps detect suspicious activity, enforce accountability, and ensure that administrative actions are in line with security policies and best practices.

## References

- [AWS Documentation: Managing Passwords for IAM Users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_admin-change-user.html)
- [AWS CLI Command: update-login-profile](https://docs.aws.amazon.com/cli/latest/reference/iam/update-login-profile.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
