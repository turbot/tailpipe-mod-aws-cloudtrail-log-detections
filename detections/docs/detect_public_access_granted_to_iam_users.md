## Description

This detection identifies IAM users that have been granted public access. Public access refers to permissions that allow any user, including unauthenticated users, to access AWS resources through an IAM user. Monitoring such configurations is critical to prevent unauthorized access and protect your AWS environment.

## Risks

Granting public access to IAM users poses significant cloud security risks. Publicly accessible IAM users can be exploited by attackers to gain unauthorized access to AWS resources. This may lead to data exfiltration, privilege escalation, or the manipulation of sensitive configurations. 

Additionally, public access to IAM users bypasses the principle of least privilege and exposes your environment to potential security breaches. Monitoring and restricting public access to IAM users is essential to maintain strict access control, minimize the attack surface, and ensure the integrity of your cloud infrastructure.

## References

- [AWS Documentation: IAM Users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html)
- [AWS CLI Command: attach-user-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-user-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
