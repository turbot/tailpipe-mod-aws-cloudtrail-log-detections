## Description

This detection identifies instances where administrative access is granted to IAM groups. Granting admin-level permissions to IAM groups provides members of the group full control over AWS resources, which can lead to significant security risks if misused or misconfigured. Monitoring such changes ensures that only authorized users have administrative privileges.

## Risks

Granting administrative access to IAM groups increases the risk of over-permissioning, where all members of the group gain unrestricted control over AWS resources. This can result in accidental or malicious changes, such as modifying security settings, deleting critical resources, or exposing sensitive data.

If unauthorized users gain access to a group with admin privileges, they can exploit these permissions to escalate access, compromise the environment, or disrupt operations. Additionally, such configurations can make compliance auditing challenging, as it becomes harder to determine who has access to sensitive resources and what actions they can perform. Monitoring for admin access grants to IAM groups helps enforce the principle of least privilege and ensures that administrative privileges are appropriately assigned and managed.

## References

- [AWS Documentation: Permissions Boundaries for IAM Entities](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [AWS CLI Command: attach-group-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-group-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
