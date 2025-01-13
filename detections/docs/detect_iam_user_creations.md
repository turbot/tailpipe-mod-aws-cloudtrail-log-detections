## Description

This detection identifies the creation of new IAM users within your AWS account. IAM users provide access to AWS resources and services, and their creation should be closely monitored to ensure they are authorized and follow security best practices. Monitoring user creation helps prevent unauthorized or unnecessary IAM user additions.

## Risks

The creation of IAM users can pose significant security risks if not properly managed. Unauthorized IAM users can be exploited to gain access to sensitive resources, escalate privileges, or execute malicious actions. Misconfigured or excessive permissions granted to new users can lead to inadvertent data exposure, resource mismanagement, or privilege escalation.

In environments where role-based access is preferred, creating IAM users instead of roles can undermine efforts to maintain centralized access control and auditing. This increases the risk of compliance violations and operational inefficiencies. Monitoring IAM user creations helps enforce security policies, prevent unauthorized access, and maintain a secure and manageable AWS environment.

## References

- [AWS Documentation: Creating an IAM User](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html)
- [AWS CLI Command: create-user](https://docs.aws.amazon.com/cli/latest/reference/iam/create-user.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
