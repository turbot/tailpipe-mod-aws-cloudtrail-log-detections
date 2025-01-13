## Description

This detection identifies instances where administrative access is granted to IAM roles. Assigning admin-level permissions to IAM roles provides unrestricted access to AWS resources, which can pose significant security risks if done without proper controls. Monitoring these changes helps ensure that administrative privileges are granted only when necessary and to trusted entities.

## Risks

Granting administrative access to IAM roles can significantly increase the attack surface of your AWS environment. Roles with admin privileges can be used to perform unrestricted actions across AWS resources, such as modifying security settings, creating or deleting resources, or accessing sensitive data. If such roles are assumed by unauthorized or compromised entities, it can lead to privilege escalation, data breaches, or other malicious activities.

Moreover, misconfigured roles with admin permissions can undermine security and compliance efforts by violating the principle of least privilege. This can make it challenging to track and audit access, increasing the risk of non-compliance with industry standards or regulatory requirements. Monitoring for admin access grants to IAM roles ensures that high-privilege permissions are tightly controlled and only granted to roles with valid, documented use cases.

## References

- [AWS Documentation: Granting Permissions Using IAM Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)
- [AWS CLI Command: attach-role-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
