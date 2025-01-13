## Description

This detection identifies IAM users added to groups with administrative privileges. Administrator groups typically have full access to all AWS resources, and attaching users to these groups should be closely monitored to prevent unauthorized or unnecessary elevation of privileges.

## Risks

Adding IAM users to administrator groups poses significant security risks, as these groups provide unrestricted access to AWS resources. Unauthorized or unnecessary inclusion of users in such groups can lead to privilege escalation, accidental resource modifications, or intentional misuse of administrative access. 

Compromised credentials of a user in an administrator group can result in account-wide breaches, including data exfiltration, resource deletion, or disabling security controls. Additionally, excessive permissions granted through administrator groups can complicate compliance efforts and undermine the principle of least privilege.

Monitoring for IAM users attached to administrator groups ensures that elevated privileges are assigned only when necessary and helps maintain a secure and compliant AWS environment.

## References

- [AWS Documentation: IAM Groups](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html)
- [AWS CLI Command: add-user-to-group](https://docs.aws.amazon.com/cli/latest/reference/iam/add-user-to-group.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
