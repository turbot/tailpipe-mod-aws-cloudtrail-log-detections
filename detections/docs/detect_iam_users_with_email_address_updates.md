## Description

This detection identifies IAM users whose associated email addresses have been updated. Email address updates for IAM users can indicate account recovery, administrative changes, or potentially unauthorized activity. Monitoring such changes is essential to ensure that email updates align with security policies and prevent misuse.

## Risks

Updating the email address associated with an IAM user can pose security risks, especially if the update is unauthorized. An attacker with the ability to change an email address can intercept password reset links or other critical notifications, potentially gaining unauthorized access to the account.

Additionally, frequent or unexplained email address changes may indicate attempts to conceal malicious activity or manipulate account configurations. Monitoring email address updates helps detect suspicious activity, enforce proper administrative oversight, and maintain the integrity of IAM accounts in your AWS environment.

## References

- [AWS Documentation: Managing IAM User Properties](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_manage.html)
- [AWS CLI Command: update-user](https://docs.aws.amazon.com/cli/latest/reference/iam/update-user.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
