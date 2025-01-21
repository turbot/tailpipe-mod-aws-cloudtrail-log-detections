## Description

This detection identifies IAM roles with managed policies attached. Managed policies are standalone policies that can be attached to multiple identities, such as users, groups, and roles. Monitoring managed policies attached to IAM roles ensures that permissions are assigned appropriately and follow security best practices.

## Risks

Attaching managed policies to IAM roles can lead to security risks if the policies are overly permissive or not reviewed regularly. Over-permissioned roles can grant access to sensitive resources, increasing the risk of privilege escalation, unauthorized access, or accidental modifications.

Additionally, using managed policies without proper governance can complicate compliance efforts, especially when policies are updated without consideration of their impact on all attached roles. Monitoring managed policies attached to IAM roles helps ensure adherence to the principle of least privilege, enabling effective permission management and reducing the attack surface.

## References

- [AWS Documentation: Managed Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [AWS CLI Command: attach-role-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
