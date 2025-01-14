## Description

This detection identifies Amazon RDS database instances where IAM database authentication is disabled. Enabling IAM database authentication allows you to use AWS Identity and Access Management (IAM) users and roles to connect to your RDS database instead of traditional database passwords, enhancing security and simplifying access management.

## Risks

Disabling IAM authentication for RDS instances forces the use of static database credentials, which increases the risk of credential leakage and unauthorized access. IAM authentication integrates with AWS services, enabling centralized credential management and temporary, securely managed access tokens.

In addition, using traditional credentials can complicate access management and auditing, especially in environments requiring fine-grained access controls or compliance with regulations like PCI DSS or GDPR. Enabling IAM authentication helps streamline access control and aligns with security best practices.

## References

- [IAM Database Authentication for MySQL and PostgreSQL](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html)
- [Securing Amazon RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.Security.html)
- [AWS CLI Command: modify-db-instance](https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-instance.html)
