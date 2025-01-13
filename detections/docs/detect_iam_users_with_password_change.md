## Description

This detection identifies IAM users who have changed their account passwords. Password changes can indicate routine updates as part of security best practices or may signal potentially unauthorized activity. Monitoring password changes ensures visibility into IAM user activities and helps detect suspicious behavior.

## Risks

Password changes for IAM users can pose risks if performed without proper oversight. Unauthorized password changes by attackers or malicious insiders can lead to compromised accounts, allowing unauthorized access to AWS resources, data exfiltration, or disruption of services.

Frequent or unexpected password changes may also indicate attempts to evade detection or manipulate account security settings. Monitoring IAM user password changes helps enforce security policies, such as password rotation schedules, and ensures that any unauthorized activities are promptly identified and investigated.

## References

- [AWS Documentation: Changing Your AWS Password](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_user-change.html)
- [AWS CLI Command: update-login-profile](https://docs.aws.amazon.com/cli/latest/reference/iam/update-login-profile.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
