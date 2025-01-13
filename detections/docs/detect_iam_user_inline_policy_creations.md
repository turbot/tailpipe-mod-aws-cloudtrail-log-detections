## Description

This detection identifies the creation of inline policies directly attached to IAM users. Inline policies define permissions and are embedded directly within an IAM user rather than being attached as standalone managed policies. Monitoring the creation of such policies is critical to prevent unauthorized or overly permissive access configurations.

## Risks

Creating inline policies for IAM users can pose significant security and operational risks. Inline policies are harder to track and manage compared to managed policies, which can lead to misconfigurations, such as granting excessive or unintended permissions. These misconfigurations increase the risk of unauthorized access, privilege escalation, or data breaches.

Additionally, inline policies directly tied to a specific user can complicate policy auditing and compliance efforts. If an inline policy is deleted or modified unintentionally, it can disrupt user permissions, potentially impacting critical workflows. Monitoring for inline policy creations ensures adherence to security best practices by encouraging the use of managed policies, which offer better control and scalability.

## References

- [AWS Documentation: Inline Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [AWS CLI Command: put-user-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/put-user-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
