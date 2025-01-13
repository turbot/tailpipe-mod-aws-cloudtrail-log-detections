## Description

This detection identifies the creation of inline policies attached directly to IAM groups. Inline policies specify permissions and are embedded within an IAM group, rather than being standalone managed policies. Monitoring these actions is critical to prevent unauthorized or overly permissive access configurations.

## Risks

Creating inline policies for IAM groups can pose significant security and operational risks. Inline policies are tied directly to a group and are harder to manage and audit compared to managed policies. This can lead to misconfigurations, such as granting excessive permissions to all members of the group, increasing the risk of privilege escalation, unauthorized access, or resource misuse.

Additionally, inline policies complicate policy auditing and compliance efforts because they lack the central visibility and reusability of managed policies. If an inline policy is unintentionally modified or deleted, it can disrupt the permissions for all group members, potentially impacting critical operations. Monitoring for inline policy creations ensures adherence to security best practices and helps enforce the principle of least privilege.

## References

- [AWS Documentation: Inline Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [AWS CLI Command: put-group-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/put-group-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
