## Description

This detection identifies IAM users with AWS Management Console access enabled. Providing console access to IAM users allows them to log in and interact with the AWS Management Console. Monitoring such configurations helps ensure that only authorized users have console access and that access aligns with security best practices.

## Risks

Enabling console access for IAM users can increase the risk of unauthorized access to AWS resources if proper security controls are not in place. Compromised credentials of a user with console access can allow attackers to make changes to configurations, access sensitive data, or disrupt critical operations.

Console access can also introduce compliance challenges, particularly if strong password policies, Multi-Factor Authentication (MFA), and activity logging are not enforced. Excessive or unnecessary console access for IAM users may violate the principle of least privilege, increasing the attack surface of your AWS environment. Monitoring for IAM users with console access ensures that such privileges are granted only when necessary and are properly secured.

## References

- [AWS Documentation: Enabling or Disabling a User’s Console Access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_enable-user.html)
- [AWS CLI Command: create-login-profile](https://docs.aws.amazon.com/cli/latest/reference/iam/create-login-profile.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
