## Description

This detection identifies IAM users with managed policies attached. Managed policies are standalone policies that provide a reusable and scalable way to assign permissions. Monitoring managed policies attached to IAM users ensures that permissions are granted appropriately and follow security best practices.

## Risks

Attaching managed policies directly to IAM users can lead to security and operational risks. Directly assigned managed policies bypass group-based access control mechanisms, making it harder to manage and audit permissions effectively. Over-permissioned policies attached to users can increase the risk of privilege escalation, unauthorized access, or accidental resource modifications.

Using managed policies for individual users also complicates governance, as updates to a managed policy affect all attached users, potentially leading to unintended consequences. Monitoring managed policies attached to IAM users helps enforce best practices, such as using IAM groups for permissions management and ensuring compliance with the principle of least privilege.

## References

- [AWS Documentation: Managed Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [AWS CLI Command: attach-user-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-user-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
