## Description

This detection identifies IAM users who have been attached to groups with administrative privileges. Administrator groups typically have full access to all AWS resources, and attaching users to these groups should be carefully monitored to prevent unauthorized or unnecessary elevation of privileges.

## Risks

Attaching IAM users to administrative groups significantly increases the risk of over-permissioning. Users in such groups gain unrestricted access to AWS resources, which can lead to unauthorized access, accidental or malicious resource modifications, or data exfiltration.

Additionally, administrative groups bypass granular role-based access control, making it harder to enforce the principle of least privilege. If credentials for a user in an admin group are compromised, attackers can leverage those privileges to disrupt services, alter configurations, or access sensitive data. Monitoring and managing IAM user attachments to admin groups is essential to maintaining a secure cloud environment and reducing the risk of privilege escalation.

## References

- [AWS Documentation: IAM Groups](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html)
- [AWS CLI Command: add-user-to-group](https://docs.aws.amazon.com/cli/latest/reference/iam/add-user-to-group.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
