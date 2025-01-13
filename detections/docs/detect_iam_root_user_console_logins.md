## Description

This detection identifies AWS Management Console login events performed by the root user. The root user in an AWS account has unrestricted administrative access, making it a highly privileged account that should only be used in exceptional circumstances. Monitoring root user logins helps ensure that this account is not used unnecessarily, reducing the risk of security incidents.

## Risks

Root user logins pose significant security risks as the root account has full administrative access to all resources in the AWS account. Unauthorized or unnecessary use of the root user can lead to severe consequences, such as account takeover, misconfiguration of critical resources, or data breaches.

Using the root account for routine operations also increases the attack surface and bypasses role-based access controls that are essential for maintaining a secure and auditable environment. Compromised root user credentials can result in complete control of the AWS account by attackers, making it critical to monitor and restrict root user activities.

Monitoring root user console logins helps identify unauthorized access, enforce best practices, and mitigate potential risks by ensuring the root account is used only when absolutely necessary.

## References

- [AWS Documentation: Best Practices for Securing the Root User](https://docs.aws.amazon.com/accounts/latest/reference/root-user-best-practices.html)
- [AWS Documentation: Viewing Root User Activity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_view-activity)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
