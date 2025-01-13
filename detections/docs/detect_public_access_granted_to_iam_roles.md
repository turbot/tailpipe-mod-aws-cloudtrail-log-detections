## Description

This detection identifies IAM roles that have been granted public access. Public access refers to permissions that allow any user, including unauthenticated users, to assume an IAM role and access AWS resources. Monitoring such configurations is critical to prevent unauthorized access and ensure a secure AWS environment.

## Risks

Granting public access to IAM roles significantly increases the risk of unauthorized access to your AWS resources. Publicly accessible roles can be exploited by attackers to gain elevated privileges, access sensitive data, or disrupt services. This can lead to data exfiltration, unauthorized modifications to resources, or the misuse of critical infrastructure.

Additionally, public access to IAM roles bypasses the principle of least privilege and weakens the security posture of your environment. Monitoring and restricting public access to IAM roles is essential to maintain strict access control and reduce the attack surface of your cloud infrastructure.

## References

- [AWS Documentation: IAM Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)
- [AWS CLI Command: attach-role-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
