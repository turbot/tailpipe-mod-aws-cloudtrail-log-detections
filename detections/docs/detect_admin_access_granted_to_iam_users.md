## Description

This detection identifies instances where administrative access is granted to IAM users. Assigning admin-level permissions to individual IAM users provides them unrestricted access to AWS resources, which can pose significant security risks if done without proper oversight. Monitoring these changes helps ensure administrative privileges are only granted when necessary and to trusted users.

## Risks

Granting administrative access to IAM users increases the risk of over-permissioning, where individuals can perform unrestricted actions across AWS resources. This can lead to accidental or intentional misuse, such as altering security configurations, deleting critical resources, or accessing sensitive data. 

If the credentials of an IAM user with admin permissions are compromised, attackers can exploit these permissions to escalate access, compromise resources, or disrupt operations. Furthermore, direct admin access to users can complicate auditing and compliance efforts, as it bypasses role-based or group-based access management practices. Monitoring for admin access grants to IAM users helps enforce the principle of least privilege and ensures that such permissions are assigned judiciously and securely.

## References

- [AWS Documentation: Permissions Boundaries for IAM Entities](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [AWS CLI Command: attach-user-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-user-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
