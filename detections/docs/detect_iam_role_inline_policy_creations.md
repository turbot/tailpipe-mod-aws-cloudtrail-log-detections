## Description

This detection identifies the creation of inline policies attached directly to IAM roles. Inline policies are embedded within a role and define specific permissions. Monitoring these activities is critical to prevent unauthorized or overly permissive configurations, ensuring IAM roles adhere to security best practices.

## Risks

Creating inline policies for IAM roles introduces significant security and operational risks. Unlike managed policies, inline policies are tied directly to a specific role, making them harder to track, audit, and reuse. Misconfigured inline policies can result in granting excessive or unintended permissions, increasing the risk of privilege escalation, unauthorized access, or data breaches.

Additionally, inline policies complicate compliance efforts by bypassing centralized policy management. If an inline policy is inadvertently deleted or modified, it can disrupt the functionality of critical resources relying on the role. Monitoring for inline policy creations ensures the principle of least privilege is enforced, reducing the risk of misconfigurations and maintaining a secure and manageable IAM environment.

## References

- [AWS Documentation: Inline Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [AWS CLI Command: put-role-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/put-role-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
