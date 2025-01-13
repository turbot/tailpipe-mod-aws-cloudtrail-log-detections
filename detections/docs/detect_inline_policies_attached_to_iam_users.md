## Description

This detection identifies IAM users with inline policies attached. Inline policies are directly embedded within an IAM user and define specific permissions. Monitoring the attachment of inline policies to IAM users helps ensure that permissions are managed centrally and follow security best practices.

## Risks

Attaching inline policies to IAM users introduces security and operational risks. Inline policies are tied directly to a user and lack the reusability and central visibility provided by managed policies. This can lead to misconfigurations, such as excessive or unintended permissions, increasing the risk of privilege escalation, unauthorized access, or data breaches.

Additionally, inline policies complicate policy auditing and compliance efforts as they are harder to track and manage compared to managed policies. If an inline policy is accidentally deleted or modified, it can disrupt the permissions for critical resources. Monitoring for inline policies attached to IAM users ensures adherence to the principle of least privilege and promotes better policy management practices.

## References

- [AWS Documentation: Inline Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [AWS CLI Command: put-user-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/put-user-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
