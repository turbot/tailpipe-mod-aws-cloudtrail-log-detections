## Description

This detection identifies IAM groups that have been granted public access. Public access refers to permissions that allow any user, including unauthenticated users, to access AWS resources. Monitoring such configurations is critical to prevent unauthorized access and maintain the security of your AWS environment.

## Risks

Granting public access to IAM groups poses significant security risks, as it allows any user, regardless of their identity or intent, to access AWS resources. This can lead to data breaches, privilege escalation, or malicious exploitation of resources. Publicly accessible groups can also be used to compromise sensitive environments, disrupt services, or launch unauthorized operations.

Additionally, public access configurations can result in non-compliance with regulatory requirements or security best practices, increasing the risk of reputational damage and operational disruptions. Monitoring for public access granted to IAM groups helps ensure that access permissions align with the principle of least privilege and are restricted to trusted and authenticated entities.

## References

- [AWS Documentation: Identity and Access Management (IAM) Groups](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html)
- [AWS CLI Command: attach-group-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-group-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
