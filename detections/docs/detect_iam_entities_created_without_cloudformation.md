## Description

This detection identifies IAM entities (users, roles, or groups) created outside of AWS CloudFormation. AWS CloudFormation enables centralized and auditable resource management, and creating IAM entities outside of it can bypass established governance, auditing, and compliance mechanisms. Monitoring such activities ensures adherence to infrastructure-as-code (IaC) best practices and prevents unauthorized resource creation.

## Risks

Creating IAM entities outside of CloudFormation introduces risks of unmanaged and untracked resources, which may not adhere to organizational security and compliance standards. Such entities may bypass automated security controls, leading to over-permissioning or inadequate configurations. This can result in unauthorized access, privilege escalation, or accidental exposure of sensitive data.

Additionally, manually created IAM entities can complicate auditing and troubleshooting, as they lack the centralized visibility and change tracking provided by IaC tools like CloudFormation. Monitoring for IAM entity creation without CloudFormation ensures consistent resource management and reinforces security best practices, such as limiting manual configuration changes and adhering to the principle of least privilege.

## References

- [AWS Documentation: AWS CloudFormation Best Practices](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html)
- [AWS Documentation: Managing IAM Users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html)
- [AWS CLI Command: create-user](https://docs.aws.amazon.com/cli/latest/reference/iam/create-user.html)
- [AWS CLI Command: create-role](https://docs.aws.amazon.com/cli/latest/reference/iam/create-role.html)
